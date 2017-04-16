#ifndef FRH
#define FRH

#include "threads/thread.h"
#include "threads/malloc.h"
#include "threads/synch.h"
#include "vm/page.h"
#include <hash.h>
#include <list.h>


struct frame {

  //page in the frame
  struct spage *sp;
  //physical address
  uint32_t * kaddr;
  struct thread *t;
  struct list_elem elem;

  //struct lock pinned;
  bool pinned;
  
};

void frametable_init(int);
bool insert_frame(struct spage *page);
//unsigned f_hash(struct hash_elem, void*);

#endif
