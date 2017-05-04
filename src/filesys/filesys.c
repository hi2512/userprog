 #include "filesys/filesys.h"
#include <debug.h>
#include <stdio.h>
#include <string.h>
#include "filesys/file.h"
#include "filesys/free-map.h"
#include "filesys/inode.h"
#include "filesys/directory.h"
#include "threads/malloc.h"
#include "threads/thread.h"

/* Partition that contains the file system. */
struct block *fs_device;

static void do_format (void);

/* Initializes the file system module.
   If FORMAT is true, reformats the file system. */
void
filesys_init (bool format) 
{
  fs_device = block_get_role (BLOCK_FILESYS);
  if (fs_device == NULL)
    PANIC ("No file system device found, can't initialize file system.");

  inode_init ();
  free_map_init ();

  if (format) 
    do_format ();

  free_map_open ();
}

/* Shuts down the file system module, writing any unwritten data
   to disk. */
void
filesys_done (void) 
{
  free_map_close ();
}

/* Creates a file named NAME with the given INITIAL_SIZE.
   Returns true if successful, false otherwise.
   Fails if a file named NAME already exists,
   or if internal memory allocation fails. */
bool
filesys_create (const char *name, off_t initial_size, bool is_dir) 
{
  if(strlen(name) == 0) {
    return false;
  }
  
  block_sector_t inode_sector = 0;
  //struct dir *dir = dir_open_root ();
  //get the dir
  struct dir * dir = NULL;
  char *filename = calloc(1, strlen(name) + 1);
  strlcpy(filename, name, strlen(name) + 1);

  char *end_pointer = strrchr(filename, '/');
  if(end_pointer == NULL) {
    if(thread_current()->cur_dir == NULL) {
      dir = dir_open_root();
    } else {
      dir = dir_reopen(thread_current()->cur_dir);
    }

  } else {
    char *just_path =  calloc(1, strlen(name) + 1);
    strlcpy(just_path, filename, strlen(name) + 1);
    char *ep = strrchr(just_path, '/');
    //  printf("ep is : %s\n", ep);
    *ep = '\0';
    //printf("ep is : %s\n", ep);
    
     dir = dir_open_path(just_path);
      
     //printf("full line is %s\n", name);
     // printf("copy line is %s\n", filename);
     filename = end_pointer + 1;

  }
  //printf("just the file is %s\n", filename);
  /*
  bool success = (dir != NULL
                  && free_map_allocate (1, &inode_sector) );
                  //&& inode_create (inode_sector, initial_size, is_dir)
		  // && dir_add (dir, filename, inode_sector));
		  */
  bool inode_add = false;
  if(is_dir) {
    inode_add = dir_create(inode_sector, 0,
		inode_get_inumber(dir_get_inode(thread_current()->cur_dir)) )
      && dir_add (dir, filename, inode_sector);
  } else {
    inode_add = inode_create(inode_sector, 0, is_dir) &&
    dir_add (dir, filename, inode_sector);
  }
  

  
  if (!(success) && inode_sector != 0) 
    free_map_release (inode_sector, 1);
  dir_close (dir);

  return success;
}



/* Opens the file with the given NAME.
   Returns the new file if successful or a null pointer
   otherwise.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
struct file *
filesys_open (const char *name)
{
  //struct dir *dir = dir_open_root ();
  struct inode *inode = NULL;
  struct dir * dir = NULL;
  char *filename = calloc(1, strlen(name) + 1);
  strlcpy(filename, name, strlen(name) + 1);

  char *end_pointer = strrchr(filename, '/');
  if(end_pointer == NULL) {
    if(thread_current()->cur_dir == NULL) {
      dir = dir_open_root();
    } else {
      dir = dir_reopen(thread_current()->cur_dir);
    }

  } else {
    
    char *just_path =  calloc(1, strlen(name) + 1);
    strlcpy(just_path, filename, strlen(name) + 1);
    char *ep = strrchr(just_path, '/');

    *ep = '\0';
    
     dir = dir_open_path(just_path);
    
     //printf("full line is %s\n", name);
     //printf("copy line is %s\n", filename);
     filename = end_pointer + 1;

  }
  // printf("just the file is %s\n", filename);
  if( strlen(filename) == 0) {
    //file is the directory
    inode = dir_get_inode(dir);
  } else {
 

    if (dir != NULL)
      dir_lookup (dir, filename, &inode);

    // printf("finished dir lookup\n");
    if(inode == NULL) {
      // printf("INODE IS NULL\n");
    }
  //ASSERT(inode != NULL)
    dir_close (dir);
  }
  return file_open (inode);
}

/* Deletes the file named NAME.
   Returns true if successful, false on failure.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
bool
filesys_remove (const char *name) 
{
  //struct dir *dir = dir_open_root ();
  struct dir * dir = NULL;
  char *filename = calloc(1, strlen(name) + 1);
  strlcpy(filename, name, strlen(name) + 1);

  char *end_pointer = strrchr(filename, '/');
  if(end_pointer == NULL) {
    if(thread_current()->cur_dir == NULL) {
      dir = dir_open_root();
    } else {
      dir = dir_reopen(thread_current()->cur_dir);
    }

  } else {
    
    char *just_path =  calloc(1, strlen(name) + 1);
    strlcpy(just_path, filename, strlen(name) + 1);
    char *ep = strrchr(just_path, '/');

    *ep = '\0';
    
     dir = dir_open_path(just_path);
    
     filename = end_pointer + 1;

  }

  //printf("just the file is %s\n", filename);
  // printf("cwd is: %d\n",
  //	 inode_get_inumber(dir_get_inode(thread_current()->cur_dir)) );
  bool success = dir != NULL && dir_remove (dir, filename);
 
  
  dir_close (dir); 
  //printf("FILESYS remove success: %d\n", success);
  return success;
}

/* Formats the file system. */
static void
do_format (void)
{
  printf ("Formatting file system...");
  free_map_create ();
  //root's root is itself
  if (!dir_create (ROOT_DIR_SECTOR, 16, ROOT_DIR_SECTOR))
    PANIC ("root directory creation failed");
  free_map_close ();
  printf ("done.\n");
}
