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

//the "clock hand"
struct list_elem *next_check;


//Eric driving
//set up the frame table with available frames
void frametable_init(int upage_limit UNUSED) {


  list_init(&f_table);
  lock_init(&f_lock);
  
  next_check = NULL;

}

//from process.c
static bool
install_page (void *upage, void *kpage, bool writable)
{
  struct thread *t = thread_current ();

  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  return (pagedir_get_page (t->pagedir, upage) == NULL
          && pagedir_set_page (t->pagedir, upage, kpage, writable));
}

//sets the next check elem
void set_nc() {
  //not at end, so next elem
  next_check = list_next(next_check);
    
  //if last goto first
  if(next_check == list_end(&f_table)) {
    next_check = list_begin(&f_table);
  }

}

//Ramon driving
//function to remove frames from frame table after process dies
void destroy_frames(struct thread *t) {
  
  lock_acquire(&f_lock);
  
  struct hash_iterator i;

  hash_first(&i, &t->spt);
  while(hash_next(&i)) {

    struct spage *page = hash_entry(hash_cur(&i), struct spage, h_elem);
    if( (page->f != NULL) && !(page->f->pinned) ) {
      if (&page->f->elem == next_check) {
        set_nc();
      }
      list_remove(&page->f->elem);
      free(page->f);
    } 
  }
  

  lock_release(&f_lock);
  
}



//get frame with second chance clock
struct frame * get_frame() {


  uint32_t *first = NULL;
  
  struct frame *res = NULL;
  if(next_check == NULL) {
    //first check
    next_check = list_begin(&f_table);
  }
  res = list_entry(next_check, struct frame, elem);
  first = res->kaddr;

  do {

    if(!res->pinned) {
      
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
      res->pinned = false;
    }

    
    set_nc();
    //stop if at the first elem checked
    res = list_entry(next_check, struct frame, elem);
  } while (res->kaddr != first);
  
  //first sweep done, again but dirty page can be evicted
    do {

    if(!res->pinned) {
      res->pinned = true;
      
      
      //check frame under first clock hand
      if(pagedir_is_accessed(res->t->pagedir, res->sp->uaddr)) {
        pagedir_set_accessed(res->t->pagedir, res->sp->uaddr, false);
      } else {
	set_nc();
        return res;
      }
      res->pinned = false;
    }

    set_nc();
    res = list_entry(next_check, struct frame, elem);
   
  } while (res->kaddr != first);
  

  //got all the way back to orignal
  return res;
}



bool insert_frame(struct spage *page) {


  
  //taken and modified from load segment
  uint32_t *kaddr = palloc_get_page(PAL_USER | PAL_ZERO);

  struct frame *f = NULL;

  
  if(kaddr == NULL) {
    //no more mem, must evict frame
    lock_acquire(&f_lock);

    f = get_frame();
    lock_release(&f_lock);

    //remove the mapping for the previous frame
    pagedir_clear_page(f->t->pagedir, f->sp->uaddr);
    //SEND TO SWAP
    if(!put_swap(f)) {
      exit(-1);
    }

    f->sp->f = NULL;
    //frame can now be used
    kaddr = f->kaddr;
   
  } else {
    //new frame
    f = malloc(sizeof(struct frame));
    if(f == NULL) {
      exit(-1);
    }

    f->pinned = true;
    
    lock_acquire(&f_lock);
    list_push_back(&f_table, &f->elem);
    lock_release(&f_lock);
  }

  
  /*
    Check if my page is in swap
   */
  if(page->swap_spot != -1) {
    //read from swap
    get_swap(kaddr, page->swap_spot);
    //mark page as no longer in swap
    page->swap_spot = -1;
  } else {
    //read from file or put zeros
    if(page->my_file != NULL) {
      //more or less from load segment
      file_seek(page->my_file, page->offset);
      // Load this page.
      if(file_read (page->my_file, kaddr, page->bytes)
         != (int) page->bytes)  {
        palloc_free_page (kaddr);
        return false; 
      }
    } 
    memset (kaddr + page->bytes, 0, page->zeros);

  }
  


  // Add the page to the process's address space.
  if(!install_page (page->uaddr, kaddr, page->writable))  {
    palloc_free_page (kaddr);
    return false; 
  }
    
    
  //put frame into frame table
  if(f == NULL) {
    exit(-1);
    return false;
  }
  f->sp = page;
  f->kaddr = kaddr;
  f->t = thread_current();
  

  page->f = f;
  //frame is ready
  f->pinned = false;

  //insert frame successful
  return true;
  
}

