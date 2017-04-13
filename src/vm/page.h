#ifndef SPH
#define SPH

#include "threads/thread.h"
#include "threads/malloc.h"
#include "threads/synch.h" 
#include <hash.h>
#include "filesys/file.h"
#include "filesys/filesys.h"

struct spage {

  struct thread *t;
  uint8_t * uaddr;
  //frame stored in
  struct frame *f;

  off_t offset;
  size_t bytes;
  size_t zeros;
  struct file *my_file;
  bool writable;

  //-1 means not in swap!!!!
  size_t swap_spot;
  
  struct hash_elem h_elem;
  
};

void init_spt(struct thread *t);
struct spage * new_spage(struct file *file, off_t ofs, uint8_t *upage,
		      size_t bytes, size_t zer_bytes, bool writable);
bool load_page(void * fault_addr);

#endif




