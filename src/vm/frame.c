#include "threads/thread.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/synch.h"
#include "threads/loader.h"
#include "vm/frame.h"
#include "vm/page.h"
#include "vm/swap.h"
#include <inttypes.h>
#include "threads/vaddr.h"
#include "userprog/syscall.h"
#include "userprog/process.h"
#include "filesys/file.h"
#include <stdio.h>
#include <string.h>
#include "userprog/pagedir.h"
#include "threads/interrupt.h"


//static struct hash f_table;
static struct list f_table;

static struct lock f_lock;

struct list_elem *next_check;


/*
bool f_less(const struct hash_elem *a, const struct hash_elem *b,
	    void *aux UNUSED) {

  struct frame *from = hash_entry(a, struct frame, h_elem);
  struct frame *to = hash_entry(b, struct frame, h_elem);
  return from->kaddr < to->kaddr;
  
  
}

unsigned f_hash(struct hash_elem *e, void *aux UNUSED) {

  struct frame *f = hash_entry(e, struct frame, h_elem);
  return hash_int((int) f->kaddr);
  
}
*/


//set up the frame table with available frames
void frametable_init(int upage_limit UNUSED) {

  //taken from palloc
  /*
  uint8_t *free_start = ptov (1024 * 1024);
  uint8_t *free_end = ptov (init_ram_pages * PGSIZE);
  size_t free_pages = (free_end - free_start) / PGSIZE;
  */
  
  //hash_init(&f_table, f_hash, f_less, NULL);
  list_init(&f_table);
  lock_init(&f_lock);
  
  next_check = NULL;

}

static bool
install_page (void *upage, void *kpage, bool writable)
{
  struct thread *t = thread_current ();

  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  return (pagedir_get_page (t->pagedir, upage) == NULL
          && pagedir_set_page (t->pagedir, upage, kpage, writable));
}

void set_nc() {
  //not at end, so next elem
  next_check = list_next(next_check);
    
  //if last goto first
  if(next_check == list_end(&f_table)) {
    next_check = list_begin(&f_table);
  }

}

//get frame with second chance clock
struct frame * get_frame() {

  //struct list_elem *first = next_check;
  uint32_t *first = NULL;
  
  struct frame *res = NULL;
  if(next_check == NULL) {
    //first check
    next_check = list_begin(&f_table);
  }
  res = list_entry(next_check, struct frame, elem);
  first = res->kaddr;
  //printf("STARTING EVICTION!!\n");
  //struct frame *test = list_entry(first, struct frame, elem);
  //printf("the last addr to check is %x\n", first);
  //TEST HERE...................
  if(res->sp->uaddr == 134524928) {
    res->pinned_frame = true;
  }
  
  do {
    // printf("checking frame addr:%x, pinned %d\n", res->kaddr,
    //res->pinned_frame);

    if(!res->pinned_frame) {
      //CHECK HERE
      res->pinned_frame = true;
      
      //check frame under first clock hand
      if(pagedir_is_accessed(res->t->pagedir, res->sp->uaddr)) {
        pagedir_set_accessed(res->t->pagedir, res->sp->uaddr, false);
      } else {
        //is the page dirty?, if so cont
        if(pagedir_is_dirty(res->t->pagedir, res->sp->uaddr)) {
          pagedir_set_dirty(res->t->pagedir, res->sp->uaddr, true);
        } else {
	  set_nc();
          //else not dirty, this is the frame
          return res;
        }
      }
    }

    //AND HERE
    res->pinned_frame = false;
    set_nc();
    /*
    //not at end, so next elem
    next_check = list_next(next_check);
    //next, if last goto first
    if(next_check == list_end(&f_table)) {
      next_check = list_begin(&f_table);
    }
    */
    //stop if at the first elem checked
    res = list_entry(next_check, struct frame, elem);
  } while (res->kaddr != first);
  //printf("FINISHED FIRST SWEEP\n");
  
  //first sweep done, again but dirty page can be evicted
    do {
      //printf("DIRTY checking frame addr:%x, pinned %d\n", res->kaddr,
      //	   res->pinned_frame);

    if(!res->pinned_frame) {
      //SAME FOR THIS ONE
      res->pinned_frame = true;
      
      
      //check frame under first clock hand
      if(pagedir_is_accessed(res->t->pagedir, res->sp->uaddr)) {
        pagedir_set_accessed(res->t->pagedir, res->sp->uaddr, false);
      } else {
	set_nc();
        return res;
      }
    }

    //!!!!!!!!!!!!!!!!!
    res->pinned_frame = false;
    set_nc();
    res = list_entry(next_check, struct frame, elem);
   
  } while (res->kaddr != first);
  

  //got all the way back to orignal
  return res;
}



bool insert_frame(struct spage *page) {

  //enum intr_level old_level;
  //old_level = intr_disable ();
  
  //taken and modified from load segment
  //void *kaddr = palloc_get_page(PAL_USER | zero);
  uint32_t *kaddr = palloc_get_page(PAL_USER | PAL_ZERO);
  //printf("uaddr to frame is: %x for %d\n", page->uaddr, thread_current()->tid);

  struct frame *f = NULL;
  //put_swap(f);
  


  
  if(kaddr == NULL) {
    //no more mem, must evict frame
    //printf("PALLOC FOR FRAME FAILED\n");
    //printf("THREAD to acquire lock is %d\n", thread_current()->tid);
    //lock_acquire(&f_lock);

    f = get_frame();
    //f = list_entry(list_prev(list_end(&f_table)), struct frame, elem);
    //printf("frame kaddr is %x\n", f->kaddr);
    //printf("the address that was mapped was: %x for thread %s\n",
    //	   pagedir_get_page(f->t->pagedir, f->sp->uaddr), f->t->name);
    pagedir_clear_page(f->t->pagedir, f->sp->uaddr);
    //printf("removing page addr %x with %x\n", f->sp->uaddr, *f->kaddr);
 
    // lock_release(&f_lock);
    //printf("GOT FRAME!!!!!!\n");
    //if dirty, send it to swap
    if(pagedir_is_dirty(f->t->pagedir, f->sp->uaddr)) {
      //SEND TO SWAP
      // printf("PAGE IS DIRTY!!!\n");
      if(!put_swap(f)) {
	//printf("put swap failed!!!!!!!!\n");
	exit(-13);
      }
   
    } else {
      printf("page is not dirty\n");
    }
      
    //remove that page as mapped

    f->sp->f = NULL;
    //clear it
    memset(f->kaddr, 0, PGSIZE);
    //frame can now be used
    kaddr = f->kaddr;
    //printf("FRAME READY FOR REALLOCATION\n");
   
  } else {
    //new frame
    //printf("allocated new frame with addr %x\n", kaddr);
    f = malloc(sizeof(struct frame));

    lock_acquire(&f_lock);
    list_push_back(&f_table, &f->elem);
    //hash_insert(&f_table, &f->h_elem);
    lock_release(&f_lock);
  }

  
  /*
    Check if my page is in swap
   */
  if(page->swap_spot != -1) {
    //read from swap
    printf("getting from swap for addr %x \n", page->uaddr);
    get_swap(kaddr, page->swap_spot);
    //mark page as no longer in swap
    page->swap_spot = -1;
  } else {
    //read from file or put zeros
    if(page->my_file != NULL) {
      //more or less from load segment
      //printf("FIle pos is %d   XXXXXXX\n", file_tell(page->my_file));
  
      file_seek(page->my_file, page->offset);
      // printf(" NEW FIle pos is %d   XXXXXXX\n", file_tell(page->my_file));
      // Load this page.
      if(file_read (page->my_file, kaddr, page->bytes)
         != (int) page->bytes)  {
        palloc_free_page (kaddr);
        return false; 
      }
    } else {
      //printf("00000000000000 frame, no file\n");
      f->pinned_frame = true;
    }
    memset (kaddr + page->bytes, 0, page->zeros);

  }
  


  // Add the page to the process's address space.
  if(!install_page (page->uaddr, kaddr, page->writable))  {
    palloc_free_page (kaddr);
    //printf("INSTALL FAILED\n");
    return false; 
  }
    
    
  //put frame into frame table
  //struct frame *f = malloc(sizeof(struct frame));
  if(f == NULL) {
    exit(-2);
    return false;
  }
  f->sp = page;
  f->kaddr = kaddr;
  f->t = thread_current();
  //f->pinned_frame = false;

  page->f = f;



  ASSERT(is_kernel_vaddr(f->kaddr))
  ASSERT( f->kaddr == pagedir_get_page(thread_current()->pagedir
					   , page->uaddr) )
  //printf("Frame inserted at phy/krnl addr: %x for uaddr: %x!!!!!\n",
  //f->kaddr, page->uaddr);

  // printf("thread name: %s\n", f->t->name);
  //intr_set_level (old_level);
  return true;
  
}
