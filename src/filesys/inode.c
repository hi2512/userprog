#include "filesys/inode.h"
#include <list.h>
#include <debug.h>
#include <round.h>
#include <string.h>
#include "filesys/filesys.h"
#include "filesys/free-map.h"
#include "threads/malloc.h"
#include "userprog/syscall.h"
#include "threads/thread.h"
#include "threads/synch.h"

/* Identifies an inode. */
#define INODE_MAGIC 0x494e4f44

/* On-disk inode.
   Must be exactly BLOCK_SECTOR_SIZE bytes long. */
struct inode_disk
  {
    // block_sector_t start;               /* First data sector. */
    //locations of block sectors
    block_sector_t direct[10];
    block_sector_t first_level;
    block_sector_t second_level;
    off_t length;                       /* File size in bytes. */

    bool directory;
    char unused[455];
    //uint32_t unused[114];
    unsigned magic;                     /* Magic number. */
    //uint32_t unused[125];               /* Not used. */
    
  };



/* Returns the number of sectors to allocate for an inode SIZE
   bytes long. */
static inline size_t
bytes_to_sectors (off_t size)
{
  return DIV_ROUND_UP (size, BLOCK_SECTOR_SIZE);
}

/* In-memory inode. */

struct inode 
  {
    struct list_elem elem;              
    block_sector_t sector;             
    int open_cnt;                      
    bool removed;                      
    int deny_write_cnt;                 
    struct inode_disk data;            
    // bool directory;

    //add here
    struct lock i_lock;
  };

bool inode_is_dir(struct inode *i) {
  return i->data.directory;
}

/* Returns the block device sector that contains byte offset POS
   within INODE.
   Returns -1 if INODE does not contain data for a byte at offset
   POS. */
static block_sector_t
byte_to_sector (const struct inode *inode, off_t pos) 
{
  /*
  printf("Running byte to sector with pos %d, inode %d, its length: %d!!!\n",
  	 pos, inode->sector, inode->data.length);
  printf("sector for the first data block is %d\n", inode->data.direct[0]);
  */
  ASSERT (inode != NULL);
  // ASSERT (pos < inode->data.length)
  /*
  if (pos < inode->data.length)
    return inode->data.start + pos / BLOCK_SECTOR_SIZE;
  else
    return -1;
  */
  if(pos < inode->data.length) {
    off_t sector = pos / BLOCK_SECTOR_SIZE;
    if(sector < 10) {
      //printf("SECTOR direct is %d with inode %d\n",
      //  inode->data.direct[sector], inode->sector);
      //is directly allocated
      return inode->data.direct[sector];
      
    } else if(sector < 138) {
      //in first indirect block
      block_sector_t *single_block = calloc(1, BLOCK_SECTOR_SIZE);
      if(single_block == NULL) {
	exit(-1);
      }
      //minus 10 for the direct blocks
      block_read(fs_device, inode->data.first_level, single_block);
      block_sector_t res = single_block[sector - 10];
      free(single_block);
      //printf("the SECTOR is a level 1: %d\n", res);
      return res;

      //(128 * 128) + 128 + 10
    } else if(sector < 16522) {
      //the second indirect block
      block_sector_t *double_block = calloc(1, BLOCK_SECTOR_SIZE);
      block_sector_t *second_level = calloc(1, BLOCK_SECTOR_SIZE);
      if( (double_block == NULL) || (second_level == NULL) ) {
	exit(-1);
      }
      block_sector_t block_location = (sector - 138) / 128;
      block_sector_t sector_location = (sector - 138) % 128;
      //get the double block
      block_read(fs_device, inode->data.second_level, double_block);
      //get the second level indirection block from previous
      block_read(fs_device, double_block[block_location], second_level);
      block_sector_t res2 = second_level[sector_location];
      free(double_block);
      free(second_level);
      //printf("the SECTOR is a level 2: %d\n", res2);
      return res2;
      
    } 
  } else {
    return -1;
    }
}

/* List of open inodes, so that opening a single inode twice
   returns the same `struct inode'. */
static struct list open_inodes;

/* Initializes the inode module. */
void
inode_init (void) 
{
  list_init (&open_inodes);
}

/* Initializes an inode with LENGTH bytes of data and
   writes the new inode to sector SECTOR on the file system
   device.
   Returns true if successful.
   Returns false if memory or disk allocation fails. */
bool
inode_create (block_sector_t sector, off_t length, bool dir)
{
  struct inode_disk *disk_inode = NULL;
  bool success = false;

  //printf("inode create: at sector %d and length %d\n", sector, length);
  
  ASSERT (length >= 0);

  /* If this assertion fails, the inode structure is not exactly
     one sector in size, and you should fix that. */
  ASSERT (sizeof *disk_inode == BLOCK_SECTOR_SIZE);

  //printf("entering inode create\n");
  disk_inode = calloc (1, sizeof *disk_inode);
  if (disk_inode != NULL)
    {
      size_t sectors = bytes_to_sectors (length);
      disk_inode->length = length;
      disk_inode->magic = INODE_MAGIC;

      disk_inode->first_level = 0xffffffff;
      disk_inode->second_level = 0xffffffff;
      disk_inode->directory = dir;
      /*
      if (free_map_allocate (sectors, &disk_inode->direct)) 
        {
          block_write (fs_device, sector, disk_inode);
          if (sectors > 0) 
            {
              static char zeros[BLOCK_SECTOR_SIZE];
              size_t i;
              
              for (i = 0; i < sectors; i++) 
                block_write (fs_device, disk_inode->direct[i], zeros);
            }
          success = true; 
        }
      */
      //printf("doing actual inode stuff, tot sectors is %d\n", sectors);
      static char zeros[BLOCK_SECTOR_SIZE];
      size_t cur_sec = 0;
      //for direct
      size_t i;
      for(i = 0; (i < 10) && (i < sectors); i++) {
	//printf("allocating direct: %d, num sectors: %d\n", i, sectors);
	if(!free_map_allocate(1, &disk_inode->direct[i])) {
	  //printf("free map allocate failed\n");
	  return false;
	}
	block_write(fs_device, disk_inode->direct[i], zeros);
	cur_sec += 1;
      }
      //printf("finished with direct\n");
      if(cur_sec == sectors) {
	goto END;
      }
      //1st indirect
      block_sector_t *f_block = calloc(1, BLOCK_SECTOR_SIZE);
      //printf("finished calloc\n");
      //allocate for the 1st level block
      if(!free_map_allocate(1, &disk_inode->first_level)) {
	return false;
      }
      //printf("fill first level block\n");
      size_t j;
      //get the sectors for the first block
      for(j = 0; (j < 128) && ((j + 10) < sectors); j++ ) {
	//printf("j: %d sectors: %d\n", j, sectors);
	if(!free_map_allocate(1, &f_block[j])) {
          //failed
	  return false;
         }
	block_write(fs_device, f_block[j], zeros);
        cur_sec += 1;
      }
      //block creation finished, now write to block
      block_write(fs_device, disk_inode->first_level, f_block);
      free(f_block);

      if(cur_sec == sectors) {
	goto END;
      }
      //printf("starting second block\n");
      //2nd level block
      block_sector_t *s_block = calloc(1, BLOCK_SECTOR_SIZE);
      //allocate for the 2nd level block
      if(!free_map_allocate(1, &disk_inode->second_level)) {
	return false;
      }
      //printf("starting deep fill\n");
      //get the required 2 deep blocks
      size_t k = 0;
      size_t n;
      for(n = 138; n < 16522; n += 128) {
	//need a deep block
	if(!free_map_allocate(1, &s_block[k])) {
	  return false;
	}
	//and allocate for it
	block_sector_t * d_block = calloc(1, BLOCK_SECTOR_SIZE);
	size_t l;
	for(l = 0; (l < 128) && ( (l + n) < sectors); l++) {
	  if(!free_map_allocate(1, &d_block[l])) {
	    return false;
	  }
	  block_write(fs_device, d_block[l], zeros);
	}
	//got a deep block, now write it at second level block location
	block_write(fs_device, s_block[k], d_block);
	free(d_block);
	
	k++;
      }
      //printf("finish 2nd level\n");
      //write the 2nd level block to disk
      
      block_write(fs_device, disk_inode->second_level, s_block);
      free(s_block);
    }
     
  //WRITE THE ACTUAL INODE
  // if(!free_map_allocate(1)) {
  //}
 END:
  block_write (fs_device, sector, disk_inode);
  
  free (disk_inode);
  success = true;
  //printf("finished inode create\n");
  return success;
}

/* Reads an inode from SECTOR
   and returns a `struct inode' that contains it.
   Returns a null pointer if memory allocation fails. */
struct inode *
inode_open (block_sector_t sector)
{
  struct list_elem *e;
  struct inode *inode;

  /* Check whether this inode is already open. */
  for (e = list_begin (&open_inodes); e != list_end (&open_inodes);
       e = list_next (e)) 
    {
      inode = list_entry (e, struct inode, elem);
      if (inode->sector == sector) 
        {
	  //printf("doing a reopen for sector %d/////////////////\n", sector);
          inode_reopen (inode);
          return inode; 
        }
    }

  /* Allocate memory. */
  inode = malloc (sizeof *inode);
  if (inode == NULL)
    return NULL;

  /* Initialize. */
  list_push_front (&open_inodes, &inode->elem);
  inode->sector = sector;
  inode->open_cnt = 1;
  inode->deny_write_cnt = 0;
  inode->removed = false;
  
  //add here
  lock_init(&inode->i_lock);
  //printf("!!!!!!!opening inode from sector %d\n", inode->sector);
  block_read (fs_device, inode->sector, &inode->data);
  return inode;
}

/* Reopens and returns INODE. */
struct inode *
inode_reopen (struct inode *inode)
{
  if (inode != NULL)
    inode->open_cnt++;
  return inode;
}

/* Returns INODE's inode number. */
block_sector_t
inode_get_inumber (const struct inode *inode)
{
  return inode->sector;
}

void disk_inode_close(struct inode_disk * disk_inode) {
  size_t sectors = bytes_to_sectors(disk_inode->length);
  size_t cleared = 0;
  //clear direct blocks
  size_t i;
  for(i = 0; (i < 10) && (cleared < sectors); i++) {
    free_map_release(disk_inode->direct[i], 1);
    cleared += 1;
  }
  if(cleared < sectors) {
    //1st level
    block_sector_t * f_block = calloc(1, BLOCK_SECTOR_SIZE);
    block_read(fs_device, disk_inode->first_level, f_block);
    size_t j;
    for(j = 0; (j < 128) && (cleared < sectors); j++) {
      free_map_release(f_block[j], 1);
      cleared += 1;
    }
    free(f_block);
  }
  if(cleared < sectors) {
    block_sector_t * s_block = calloc(1, BLOCK_SECTOR_SIZE);
    block_read(fs_device, disk_inode->second_level, s_block);
    size_t k;
    size_t l;
    //iterating over deep blocks
    for(k = 0; (k < 128); k++) {
      if(cleared >= sectors) {
	break;
      }
      //get deep block
      block_sector_t * d_block = calloc(1, BLOCK_SECTOR_SIZE);
      block_read(fs_device, s_block[k], d_block);
      for(l = 0; (l < 128) && (cleared < sectors); l++) {
	free_map_release(d_block[l], 1);
	cleared += 1;
      }
      free(d_block);
    }
    free(s_block);
  }
  
}

/* Closes INODE and writes it to disk. (Does it?  Check code.)
   If this was the last reference to INODE, frees its memory.
   If INODE was also a removed inode, frees its blocks. */
void
inode_close (struct inode *inode) 
{
  /* Ignore null pointer. */
  if (inode == NULL)
    return;

  /* Release resources if this was the last opener. */
  if (--inode->open_cnt == 0)
    {
      /* Remove from inode list and release lock. */
      list_remove (&inode->elem);
 
      /* Deallocate blocks if removed. */
      if (inode->removed) 
        {
          free_map_release (inode->sector, 1);
          //free_map_release (inode->data.start,
	  //                bytes_to_sectors (inode->data.length)); 
	  disk_inode_close(&inode->data);
	}

      free (inode); 
    }
  //???
  // block_write(fs_device, inode->sector, inode);
  
}

/* Marks INODE to be deleted when it is closed by the last caller who
   has it open. */
void
inode_remove (struct inode *inode) 
{
  ASSERT (inode != NULL);
  inode->removed = true;
}

/* Reads SIZE bytes from INODE into BUFFER, starting at position OFFSET.
   Returns the number of bytes actually read, which may be less
   than SIZE if an error occurs or end of file is reached. */
off_t
inode_read_at (struct inode *inode, void *buffer_, off_t size, off_t offset) 
{
  uint8_t *buffer = buffer_;
  off_t bytes_read = 0;
  uint8_t *bounce = NULL;

  //printf("READING INODE %d, size %d, offset %d\n",
  //	 inode->sector, size, offset);

  while (size > 0) 
    {
      /* Disk sector to read, starting byte offset within sector. */
      block_sector_t sector_idx = byte_to_sector (inode, offset);
      //printf("Reading sector: %d with inode %d\n",
      //     sector_idx, inode->sector);
      

      
      int sector_ofs = offset % BLOCK_SECTOR_SIZE;

      /* Bytes left in inode, bytes left in sector, lesser of the two. */
      off_t inode_left = inode_length (inode) - offset;
      int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
      int min_left = inode_left < sector_left ? inode_left : sector_left;

      /* Number of bytes to actually copy out of this sector. */
      int chunk_size = size < min_left ? size : min_left;
      if (chunk_size <= 0)
        break;

      if (sector_ofs == 0 && chunk_size == BLOCK_SECTOR_SIZE)
        {
          /* Read full sector directly into caller's buffer. */
          block_read (fs_device, sector_idx, buffer + bytes_read);
        }
      else 
        {
          /* Read sector into bounce buffer, then partially copy
             into caller's buffer. */
          if (bounce == NULL) 
            {
              bounce = malloc (BLOCK_SECTOR_SIZE);
              if (bounce == NULL)
                break;
            }
          block_read (fs_device, sector_idx, bounce);
          memcpy (buffer + bytes_read, bounce + sector_ofs, chunk_size);
        }
      
      /* Advance. */
      size -= chunk_size;
      offset += chunk_size;
      bytes_read += chunk_size;
    }
  free (bounce);

  //printf(" COMPLETE\n");
  return bytes_read;
}

bool extend_inode(struct inode_disk * disk_inode, off_t size) {

  //printf("STARTING EXTEND INODE to size %d\n", size);
  size_t sectors = bytes_to_sectors (size);
  static char zeros[BLOCK_SECTOR_SIZE];
  size_t cur_sectors = bytes_to_sectors(disk_inode->length);

  //printf("cur sectors: %d, needed sectors: %d\n", cur_sectors, sectors);
  //see if any direct sectors needed
  size_t i; 
  for(i = cur_sectors; (i < 10) && (cur_sectors < sectors); i++) {
    if(!free_map_allocate(1, &disk_inode->direct[i])) {
      return false;
    }
    block_write(fs_device, disk_inode->direct[i], zeros);
    //update current sectors
    cur_sectors += 1;
    //printf("cur_sectors is now %d, in direct[%d] is %d\n",
    //	   cur_sectors, i, disk_inode->direct[i]);
  }
  //1st indirect
  if(sectors > cur_sectors) {
    //create the first level block if necessary, else use what is there
    block_sector_t *f_block = calloc(1, BLOCK_SECTOR_SIZE);
    if(disk_inode->first_level == 0xffffffff) {
      //allocate for the 1st level block
      if(!free_map_allocate(1, &disk_inode->first_level)) {
        return false;
      }   
    } else {
      block_read(fs_device, disk_inode->first_level, f_block);
    }
    
    size_t j;
    //get the sectors for the first block
    for(j = cur_sectors - 10; (j < 128) && ( (cur_sectors) < sectors); j++ ) {
      if(!free_map_allocate(1, &f_block[j])) {
        //failed
        return false;
       }
      block_write(fs_device, f_block[j], zeros);
      cur_sectors += 1;
      //printf("in 1ST level, cur sec: %d\n", cur_sectors);
    }
    //block creation or addition finished, now write to block
    block_write(fs_device, disk_inode->first_level, f_block);
    free(f_block);
  }

  if(sectors > cur_sectors) {
    //2nd level block
    block_sector_t *s_block = calloc(1, BLOCK_SECTOR_SIZE);
    if(disk_inode->second_level == 0xffffffff) {
      //allocate for the 2nd level block
      if(!free_map_allocate(1, &disk_inode->second_level)) {
	return false;
      }
    } else {
      block_read(fs_device, disk_inode->second_level, s_block);
    }
    
    //get the required 2 deep blocks

    //k is the calculation for the index of deep block in the 2nd level
    size_t k = (cur_sectors - 138) / 128;
    size_t p;
    for(p = cur_sectors - 138; p < 16384 && (cur_sectors < sectors);
	p += 128) {
      block_sector_t * d_block = calloc(1, BLOCK_SECTOR_SIZE);
      //need a deep block, check if should be there or alloc needed
      if(p % 128 == 0) {
	if(!free_map_allocate(1, &s_block[k])) {
          return false;
        }
      } else {
	//deep block should already be there
	block_read(fs_device, s_block[k], d_block);
      }
      
      //and allocate for it
      size_t l;
      //calc is the index
      for(l = ((cur_sectors - 138) % 128); (l < 128) &&
	    (cur_sectors < sectors); l++) {
	if(!free_map_allocate(1, &d_block[l])) {
	  return false;
	}
	block_write(fs_device, d_block[l], zeros);
	cur_sectors += 1;
	//printf("in 2nd level, cur sec: %d\n", cur_sectors);
      }
      //finished with deep block, now write it at second level block location
      block_write(fs_device, s_block[k], d_block);
      free(d_block);
      
      k++;
    }
    //write the 2nd level block to disk
    block_write(fs_device, disk_inode->second_level, s_block);
    free(s_block);

  }
  
  disk_inode->length = size;
  //printf("DONE WITH EXTEND INODE with new length %d\n", disk_inode->length);

  return true;
}


/* Writes SIZE bytes from BUFFER into INODE, starting at OFFSET.
   Returns the number of bytes actually written, which may be
   less than SIZE if end of file is reached or an error occurs.
   (Normally a write at end of file would extend the inode, but
   growth is not yet implemented.) */
off_t
inode_write_at (struct inode *inode, const void *buffer_, off_t size,
                off_t offset) 
{
  const uint8_t *buffer = buffer_;
  off_t bytes_written = 0;
  uint8_t *bounce = NULL;

  if (inode->deny_write_cnt)
    return 0;

  //printf("SSSSSstarting inode write with inode %d\n", inode->sector);
  //printf("inode data length is: %d and offset: %d, size is %d\n",
  //	   inode->data.length, offset, size);
  lock_acquire(&inode->i_lock);
  //does the file need to be extended?
  if(inode->data.length < (offset + size) ) {
    extend_inode(&inode->data, size + offset);
    //WRITE EXTENSION BACK TO THE INODE!!!!!!
    block_write(fs_device, inode->sector, &inode->data);
  }
  
  while (size > 0) 
    {
      /* Sector to write, starting byte offset within sector. */
      block_sector_t sector_idx = byte_to_sector (inode, offset);
      //printf("SECTOR TO WRITE TO IS: %d with %d\n",
      //        sector_idx, inode->sector);
      
      int sector_ofs = offset % BLOCK_SECTOR_SIZE;

      /* Bytes left in inode, bytes left in sector, lesser of the two. */
      off_t inode_left = inode_length (inode) - offset;
      int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
      int min_left = inode_left < sector_left ? inode_left : sector_left;

      /* Number of bytes to actually write into this sector. */
      int chunk_size = size < min_left ? size : min_left;
      if (chunk_size <= 0)
        break;

      if (sector_ofs == 0 && chunk_size == BLOCK_SECTOR_SIZE)
        {
          /* Write full sector directly to disk. */
          block_write (fs_device, sector_idx, buffer + bytes_written);
        }
      else 
        {
          /* We need a bounce buffer. */
          if (bounce == NULL) 
            {
              bounce = malloc (BLOCK_SECTOR_SIZE);
              if (bounce == NULL)
                break;
            }

          /* If the sector contains data before or after the chunk
             we're writing, then we need to read in the sector
             first.  Otherwise we start with a sector of all zeros. */
          if (sector_ofs > 0 || chunk_size < sector_left) 
            block_read (fs_device, sector_idx, bounce);
          else
            memset (bounce, 0, BLOCK_SECTOR_SIZE);
          memcpy (bounce + sector_ofs, buffer + bytes_written, chunk_size);
          block_write (fs_device, sector_idx, bounce);
        }

      /* Advance. */
      size -= chunk_size;
      offset += chunk_size;
      bytes_written += chunk_size;

      
      
    }
  free (bounce);

  //printf("write finished\n");
  lock_release(&inode->i_lock);
  return bytes_written;
}

/* Disables writes to INODE.
   May be called at most once per inode opener. */
void
inode_deny_write (struct inode *inode) 
{
  inode->deny_write_cnt++;
  ASSERT (inode->deny_write_cnt <= inode->open_cnt);
}

/* Re-enables writes to INODE.
   Must be called once by each inode opener who has called
   inode_deny_write() on the inode, before closing the inode. */
void
inode_allow_write (struct inode *inode) 
{
  ASSERT (inode->deny_write_cnt > 0);
  ASSERT (inode->deny_write_cnt <= inode->open_cnt);
  inode->deny_write_cnt--;
}

/* Returns the length, in bytes, of INODE's data. */
off_t
inode_length (const struct inode *inode)
{
  return inode->data.length;
}
