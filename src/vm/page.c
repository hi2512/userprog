#include "threads/malloc.h"
#include "threads/synch.h" 
#include "threads/palloc.h"
#include "threads/synch.h"
#include "threads/loader.h"
#include "vm/frame.h"
#include <inttypes.h>
#include "threads/vaddr.h"
#include "userprog/syscall.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/vaddr.h"
#include <hash.h>
#include "threads/thread.h"

//Eric driving
//functions for the hash table
bool p_less(const struct hash_elem *a, const struct hash_elem *b,
	    void *aux UNUSED) {

  struct spage *from = hash_entry(a, struct spage, h_elem);
  struct spage *to = hash_entry(b, struct spage, h_elem);
  return from->uaddr < to->uaddr;
  
  
}

unsigned p_hash(struct hash_elem *e, void *aux UNUSED) {

  struct spage *s = hash_entry(e, struct spage, h_elem);
  return hash_int((int) s->uaddr);
  
}

//init for a thread
void init_spt(struct thread *t) {

  hash_init(&t->spt, p_hash, p_less, NULL);
  
}

bool load_stack(void *addr) {

  struct spage *st = new_spage(NULL, 0, (uint8_t *) pg_round_down(addr),
			       0, 0, true);
  bool success = load_page(st->uaddr);
  if(!success) {
    exit(-1);
  } 

  
  return success;
}

//setup the new spt entry
struct spage * new_spage(struct file *file, off_t ofs, uint8_t *upage,
			 size_t bytes, size_t zero_bytes,  bool writable) {

  struct spage *sp = malloc(sizeof(struct spage));
  if(sp == NULL) {
    //not enough memory
    exit(-1);
  }
  sp->t = thread_current();
  sp->uaddr = upage;
  sp->offset = ofs;
  sp->bytes = bytes;
  sp->zeros = zero_bytes;

  sp->my_file = file;
  sp->writable = writable;

  //not in swap
  sp->swap_spot = -1;
  sp->f = NULL;

  //add to spt
  struct thread *cur = thread_current();
  lock_acquire(&cur->spt_lock);

  if(hash_insert(&thread_current()->spt, &sp->h_elem) != NULL) {
    //printf("ALREADY ELEMENT OF HASH?\n");
  } 
  lock_release(&cur->spt_lock);
      

  return sp;

}

//page faulted, so load that page and put into a frame
bool load_page(void *fault_addr) {

  //get the aligned address for the page table
  uint8_t * faddr = (uint8_t *) fault_addr;
  uint8_t * align_uaddr = (uint8_t *) pg_round_down(fault_addr);
    ASSERT (is_user_vaddr(fault_addr))


  //get kaddr by using this with hash_find
  struct spage adr;
  adr.uaddr = align_uaddr;

  struct spage *to_load = NULL;
  struct hash_elem *he = hash_find(&thread_current()->spt, &adr.h_elem);
  if(he == NULL) {
    // printf("ADDRESS NOT FOUND IN SPT\n");
    return false;
  } else {
    //found the entry and load it
    to_load = hash_entry(he, struct spage, h_elem);
    return insert_frame(to_load);
  }
  
  

  
}

//functionally the same but locks the frame
bool load_page_lock(void *fault_addr) {

  uint8_t * faddr = (uint8_t *) fault_addr;
  uint8_t * align_uaddr = (uint8_t *) pg_round_down(fault_addr);
    ASSERT (is_user_vaddr(fault_addr))

  //get kaddr
  struct spage adr;
  adr.uaddr = align_uaddr;

  struct spage *to_load = NULL;
  struct hash_elem *he = hash_find(&thread_current()->spt, &adr.h_elem);
  if(he == NULL) {
    //printf("ADDRESS NOT FOUND IN SPT\n");
    return false;
  } else {
    to_load = hash_entry(he, struct spage, h_elem);
    bool suc = insert_frame(to_load);
    if(suc) {
      to_load->f->pinned = true;
    }
    return suc;
  }
  
  

  
}



