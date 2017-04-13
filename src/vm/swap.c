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

void swap_init() {

  swap_block = block_get_role(BLOCK_SWAP);
  //create bitmap with open swap spots
  swap_map = bitmap_create(block_size(swap_block) / page_sector);
  lock_init(&s_lock);

  
}



bool put_swap(struct frame *f) {

  // printf("START PUT SWAPZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ\n");
  // printf("frame's kaddr: %x\n", f->kaddr);
  lock_acquire(&s_lock);
  //printf("pgsize %d, block sector size: %d, %d\n", PGSIZE, BLOCK_SECTOR_SIZE
  //,  block_size(swap_block) / page_sector);
  /*
  //testing stuff
  char d[512];
  int i;
  for(i = 0; i < 512; i++) {
    d[i] = 'a';
  }
  for(i = 0; i < 9000; i++) {
    printf("check sector %d,\n", i);
    block_write(swap_block, i, d);
  }
  */

  //take this frame and put it in swap
  //find spot in bitmap
  size_t spot = bitmap_scan_and_flip(swap_map, 0, 1, false);
  if(spot == BITMAP_ERROR) {
    //swap full
    //do something
    printf("BITMAP ERROR\n");
    lock_release(&s_lock);
    return false;
  }
  //x 8 for the correct mapping
   spot *= page_sector;

  //write in swap block
  //8 parts for the blocks in a page
   int x = 0;
   printf("writing to swap starting from addr %x with %x\n", f->sp->uaddr + x, *(f->kaddr + x));
  int i;
  for(i = 0; i < page_sector; i++) {
    // printf(", %x ", f->kaddr + (page_sector * i));
    block_write(swap_block, spot + i, f->kaddr +
		(i * page_sector)); 
  }
  // printf("spot is: %x\n", f->kaddr);
  //mark the page as in swap
  f->sp->swap_spot = spot;

  //bitmap_dump(swap_map);
  lock_release(&s_lock);
  //printf("PUT SWAP FINISHEDZZZZZZZZZZZ with swap spot %d\n", f->sp->swap_spot);
  return true;
}

//writes from swap to kaddr from from_spot
bool get_swap(uint32_t *kaddr, size_t from_spot) {

  lock_acquire(&s_lock);
  size_t map_spot = from_spot;
  //printf("GET SWAPPPPPPPPPPPPP  spot is %d and to kaddr %x\n",
  //	 map_spot, kaddr);

  //check spot 
  if(!bitmap_contains(swap_map, map_spot, 1, true)) {
    //error
    //do something
    printf("BITMAP ERROR get swap\n");
    lock_release(&s_lock);
    return false;
  }
  //put all parts into physical memory
  int i;
  for(i = 0; i < page_sector; i++) {
    block_read(swap_block, map_spot + i, kaddr + (page_sector * i)); 
  }

  //mark as open spot
  bitmap_set(swap_map, map_spot, false);
  lock_release(&s_lock);
  printf("got swap finished!!!!!!!!!! read %x\n", *kaddr);
  return true;
}

