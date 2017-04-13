#ifndef SWH
#define SWH
/*
#include "threads/thread.h"
#include "threads/malloc.h"
#include "threads/synch.h" 
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/malloc.h"
*/
#include "devices/block.h"

void swap_init();
bool put_swap(struct frame *f);
bool get_swap(uint8_t *vaddr, size_t swap_spot);




#endif