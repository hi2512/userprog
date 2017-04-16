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
  //printf("going to stack load page....");
  bool success = load_page(st->uaddr);
  if(!success) {
    exit(-1);
  } 
  //CHECK THIS LATER
  //st->f->pinned_frame = true;
  //lock_acquire(&st->f->pinned);
  
  return success;
}

struct spage * new_spage(struct file *file, off_t ofs, uint8_t *upage,
			 size_t bytes, size_t zero_bytes,  bool writable) {

  struct spage *sp = malloc(sizeof(struct spage));
  if(sp == NULL) {
    //not enough memory
    exit(-2);
  }
  sp->t = thread_current();
  sp->uaddr = upage;
  sp->offset = ofs;
  sp->bytes = bytes;
  sp->zeros = zero_bytes;

  //printf("bytes spage: %d\n", (int) sp->bytes);
  //printf("bytes spage offset: %d\n",(int) sp->offset);
  sp->my_file = file;
  sp->writable = writable;

  //not in swap
  sp->swap_spot = -1;
  sp->f = NULL;

  //add to spt
  struct thread *cur = thread_current();
  // printf("lock acquire.......");
  lock_acquire(&cur->spt_lock);
  // printf("DONEEEEE!\n");

  if(hash_insert(&thread_current()->spt, &sp->h_elem) != NULL) {
    //printf("CHECK:    ALREADY ELEMENT OF HASH?\n");
  } else {
    ASSERT (is_user_vaddr(upage))
      //printf("ADDED TO SPT WITH UPAGE: %x ofs: %d bytes: %d\n", upage, ofs, bytes);
  }
  lock_release(&cur->spt_lock);
  //printf("lock RELEASED!!!!!!\n");
      

  return sp;

}

//page faulted, so load that page and put into a frame
bool load_page(void *fault_addr) {

  
  uint8_t * faddr = (uint8_t *) fault_addr;
  //printf("The faulting addr is %x\n", faddr);
  uint8_t * align_uaddr = (uint8_t *) pg_round_down(fault_addr);
  //printf("The addr after align is %x\n", align_uaddr);
  ASSERT (is_user_vaddr(fault_addr))

  //printf("spans to addr: %x\n", (uint8_t *) pg_round_up(fault_addr + 1));

  //get kaddr
  struct spage adr;
  adr.uaddr = align_uaddr;

  struct spage *to_load = NULL;
  struct hash_elem *he = hash_find(&thread_current()->spt, &adr.h_elem);
  if(he == NULL) {
    // printf("ADDRESS NOT FOUND IN SPT\n");
    return false;
  } else {
    //printf("page found!!\n");
    to_load = hash_entry(he, struct spage, h_elem);
    //printf("Spage dt bytes: %d, zeros: %d\n",to_load->bytes, to_load->zeros);
    //printf("INserting frame!!\n");
    return insert_frame(to_load);
  }
  
  

  
}

bool load_page_lock(void *fault_addr) {

  
  uint8_t * faddr = (uint8_t *) fault_addr;
  //printf("The faulting addr is %x\n", faddr);
  uint8_t * align_uaddr = (uint8_t *) pg_round_down(fault_addr);
  // printf("The addr after align is %x\n", align_uaddr);
  ASSERT (is_user_vaddr(fault_addr))

  //printf("spans to addr: %x\n", (uint8_t *) pg_round_up(fault_addr + 1));

  //get kaddr
  struct spage adr;
  adr.uaddr = align_uaddr;

  struct spage *to_load = NULL;
  struct hash_elem *he = hash_find(&thread_current()->spt, &adr.h_elem);
  if(he == NULL) {
    //printf("ADDRESS NOT FOUND IN SPT\n");
    return false;
  } else {
    //printf("page found!!\n");
    to_load = hash_entry(he, struct spage, h_elem);
    //printf("Spage dt bytes: %d, zeros: %d\n",to_load->bytes, to_load->zeros);
    //printf("INserting frame!!\n");
    bool suc = insert_frame(to_load);
    if(suc) {
      to_load->f->pinned = true;
    }
    return suc;
  }
  
  

  
}



