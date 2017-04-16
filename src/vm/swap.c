#include "threads/thread.h"
#include "threads/malloc.h"
#include "threads/vaddr.h"
#include "threads/synch.h"
#include "threads/loader.h"
#include <bitmap.h>
#include <stdio.h>
#include "vm/page.h"
#include "vm/frame.h"
#include "devices/block.h"

static struct block *swap_block;

static struct bitmap *swap_map;
static struct lock s_lock;

//EQUALS 8
//8 block sectors to a page, PGSIZE / BLOCK_SECTOR_SIZE
static int page_sector = PGSIZE / BLOCK_SECTOR_SIZE;

//Eric driving
void swap_init() {

  swap_block = block_get_role(BLOCK_SWAP);
  //create bitmap with open swap spots
  swap_map = bitmap_create(block_size(swap_block) / page_sector);
  lock_init(&s_lock);

  
}



bool put_swap(struct frame *f) {

  lock_acquire(&s_lock);
  //take this frame and put it in swap
  //find spot in bitmap
  size_t spot = bitmap_scan_and_flip(swap_map, 0, 1, false);
  if(spot == BITMAP_ERROR) {
    //swap full
    //printf("BITMAP ERROR\n");
    lock_release(&s_lock);
    return false;
  }
  //x 8 for the correct mapping
   spot *= page_sector;

  //write in swap block
  //8 parts for the blocks in a page
  int i;
  for(i = 0; i < page_sector; i++) {
    block_write(swap_block, spot + i, ((void *) f->kaddr) +
		(i * BLOCK_SECTOR_SIZE));
  }
  //mark the page as in swap
  f->sp->swap_spot = spot;

  lock_release(&s_lock);
  return true;
}

//writes from swap to kaddr from from_spot
bool get_swap(uint32_t *kaddr, size_t from_spot) {

  lock_acquire(&s_lock);
  //this is the spot in the bitmap
  size_t map_spot = from_spot / page_sector;

  //check spot 
  if(!bitmap_contains(swap_map, map_spot, 1, true)) {
    //error
    //printf("BITMAP ERROR get swap\n");
    lock_release(&s_lock);
    return false;
  }
  //put all parts into physical memory
  int i;
  for(i = 0; i < page_sector; i++) {
    block_read(swap_block, from_spot + i, ((void *)  kaddr)
	       + (BLOCK_SECTOR_SIZE * i));
  }

  //mark as open spot
  bitmap_set(swap_map, map_spot, false);
  lock_release(&s_lock);
  return true;
}


