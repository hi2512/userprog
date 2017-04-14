#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "devices/shutdown.h"
#include "threads/synch.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "threads/malloc.h"
#include "vm/page.h"

static void syscall_handler (struct intr_frame *);


static struct lock file_lock;


tid_t exec(const char *cmd_line);
bool create(const char *file, unsigned initial_size);
bool remove(const char *file);
void seek(int fd, unsigned position);
unsigned tell(int fd);
void close(int fd);

bool is_mapped(int *esp);
bool buf_map(void * buf, int size);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init(&file_lock);
}

//Ramon driving
bool addr_valid(int *esp) {
  return (esp != NULL)  &&  (is_user_vaddr(esp)) ;
}


//HERE






//TRY TO LOAD PAGE IF NOT MAPPED???????????


bool is_mapped(int *esp) {
  
  int *e = (int *) pagedir_get_page(thread_current()->pagedir, esp);
  
  return ( e != NULL );
}

bool stack_fault_sys(uint8_t * esp, uint8_t * fault_addr) {
  //printf("SYS comparing esp: %p to fault addr: %p\n", esp , fault_addr);
  //printf("esp is user: %d, fault_addr is user: %d\n",
  // is_user_vaddr(esp), is_user_vaddr(fault_addr));
  return (fault_addr == (esp - 32)) || (fault_addr == (esp - 4))
    || (fault_addr >= esp);
}

bool buf_map(void * buf, int size) {

  //printf("BUFMAP CALLED for size %d\n", size);
  struct thread *cur = thread_current();
  uint8_t *l_buf = (uint8_t *) buf;
  int i;
  for(i = 0; i < size; i++) {
    if(!addr_valid(buf + i)) {
      exit(-1);
    }
     //printf("%d: CHECKING ADDR: %x\n", i, l_buf);
    if(!is_mapped(l_buf)) {
      //printf("not mapped FOUND\n");
       if(stack_fault_sys(cur->s_esp, l_buf)) {
	 load_stack(buf + i);
       }
       //printf("LOAD PAGE FROM BUF MAPNNNNNNNNNNNNN/n");
       load_page(buf + i);
      //return false;
      }
    l_buf++;
  }
  //printf("returning true\n");
  return true;
}


//function to read user addresses
int *arg(int *esp, int num) {

  // printf("user addr: %p\n", (void *)  esp);
  
  int *res = NULL;
  int *t = esp;
  t += num;
  // printf("user addr after add: %x of %d\n", (void *)  t, num);
  
  if(!addr_valid(t)) {
    exit(-1);
  }

  //checks the page directory to get a valid address
  res = (int *) pagedir_get_page(thread_current()->pagedir, t);
  ASSERT (is_kernel_vaddr(res));

  //printf("krnl addr: %x\n", (void *)  res);
  
  return res;
  
}

//Eric driving
static void
syscall_handler (struct intr_frame *f) 
{

  int *a = f->esp;


  //do validity check
  if( !( addr_valid(a) && is_mapped(a) )  ) {
    //kill b/c bad pointer
    exit(-1);
    
  }

  thread_current()->s_esp = a;

  
  //switch depending on enums in syscall-nr.h
  switch(*a) {
    case SYS_HALT :
      halt();
      break;
    case SYS_EXIT :
      exit(*arg(a, 1));
      break;
    case SYS_EXEC :
      f->eax = exec(*arg(a, 1));
      break;
    case SYS_WAIT:
      f->eax = wait(*arg(a, 1));
      break;
    case SYS_CREATE :
      f->eax = create(*arg(a, 1), *arg(a, 2)); 
      break;
    case SYS_REMOVE :
      f->eax = remove(*arg(a, 1));
      break;
    case SYS_OPEN :
      f->eax = open(*arg(a, 1));
      break;
    case SYS_FILESIZE :
      f->eax = filesize(*arg(a, 1));
      break;
    case SYS_READ :
      // printf("buffer IS: %x\n", *arg(a,2));
      buf_map(*arg(a, 2), (int) *arg(a, 3));
      f->eax = read(*arg(a, 1), *arg(a, 2), *arg(a, 3));
      break;
    case SYS_WRITE :
      buf_map(*arg(a, 2), (int) *arg(a, 3));
      f->eax = write(*arg(a, 1), *arg(a, 2), *arg(a, 3));
      break;
    case SYS_SEEK :
      seek(*arg(a, 1), *arg(a, 2));
      break;
    case SYS_TELL :
      f->eax = tell(*arg(a, 1));
      break;
    case SYS_CLOSE :
      close(*arg(a, 1));
      break;
  }
  
  

}

void halt() {

  shutdown_power_off();

}

//function to get exit_status from a tid
struct exit_status *get_es_tid(tid_t tid) {

  struct exit_status *res = NULL;
  struct thread *cur = thread_current();
  struct list_elem *e = list_begin(&cur->children);
  while(e != list_end(&cur->children)) {
    
    struct exit_status *es = list_entry(e, struct exit_status, elem);
    if(es->tid == tid) {
      res = es;
      break;
    }
    e = list_next(e);
  }

  return res;
}




void exit(int status) {


  struct thread *cur = thread_current();


  printf("%s: exit(%d)\n", cur->name_only, status);
  //ASSERT (1 == 0)
  
  if(cur->parent != NULL) {
    struct exit_status *es = cur->status_in_parent;
    es->status = status;
    cur->exit_status = status;
    //set for a waiting thread
    sema_up(&es->ready);
  } 

  thread_exit();
}


tid_t exec(const char *cmd_line) {

  if(!addr_valid(cmd_line) || !(is_mapped(cmd_line)) ) {
    exit(-1);
  }
  lock_acquire(&file_lock);
  //check for load to be finished????
  sema_init(&thread_current()->exec_sem, 0);
  tid_t res = process_execute(cmd_line);
  //wait for thread to finish loading
  sema_down(&thread_current()->exec_sem);
  struct exit_status *es = get_es_tid(res);
  if( es->load_success == 0 ) {
    //load failed
    lock_release(&file_lock);
    return -1;
  }
  lock_release(&file_lock);
  return res;
  
}


int wait(tid_t pid) {

  return process_wait(pid);
  
  
}

bool create(const char *file, unsigned initial_size) {
  
  if(!is_mapped(file)) {
    exit(-1);
  }
  lock_acquire(&file_lock);
  bool res = filesys_create(file, initial_size);
  lock_release(&file_lock);
  return res;
}



bool remove(const char *file) {

  lock_acquire(&file_lock);
  bool res = filesys_remove(file);
  lock_release(&file_lock);
  return res;
}

//WHEN ACCESSING FILE IN ARRAY
//ALWAYS ADJUST + OR - 2 DUE TO 0 AND 1 BEING RESERVE
int add_file(struct file *f) {

  int fd = -1;

  struct thread *cur = thread_current();
  int i;
  //128 b/c file limit
  for(i = 0; i < 128; i++) {
    if(cur->files[i] == NULL) {
      //there is an open spot
      cur->files[i] = f;
      //plus 2 to count for 0 and 1
      fd = i + 2;
      break;
    }
  }
  return fd;
}


int open(const char *file) {

  
  if(!is_mapped(file)) {
    exit(-1);
    
  }
  
  lock_acquire(&file_lock);
  struct file *f = filesys_open(file);
  if(f == NULL) {
    lock_release(&file_lock);
    return -1;
  }
  int res = add_file(f);
  //mark file as open in the thread
  lock_release(&file_lock);
  return res;
}

int filesize(int fd) {

  lock_acquire(&file_lock);
  struct file *f = thread_current()->files[(fd - 2)];
  if(f == NULL) {
    //no file here
    lock_release(&file_lock);
    return -1;
  }
  int res = file_length(f);
  lock_release(&file_lock);
  return res;
}



int read(int fd, void *buffer, unsigned size) {

  //check for valid fd and buffer
  // printf("addr valid: %d\n", addr_valid(buffer));
  //printf("is mapped %d\n", is_mapped(buffer));
  //printf("buf_map: %d\n", buf_map(buffer, (int) size));
  // if( (fd < 0) || (fd == 1) ||  (fd > 129) ||  (!addr_valid(buffer))  
  //    ||  (!is_mapped(buffer)) ) {
  if( (fd < 0) || (fd == 1) ||  (fd > 129) ) {
    exit(-1);

  }
 
  lock_acquire(&file_lock);
  if(fd == 0) {
    int i;
    int s = (int) size;
    uint8_t *b = (uint8_t *) buffer;
    for(i = 0; i < s; i++) {
      uint8_t key = input_getc();
      *b = key;
      b += 1;
    }
    lock_release(&file_lock);
    return size;
  }
  struct file *f = thread_current()->files[(fd - 2)];
  if(f == NULL) {
    lock_release(&file_lock);
    return -1;
  } else {
    //printf("entering file read\n");
    //uint8_t *fu = malloc(size);
    off_t res = file_read(f, buffer, (off_t) size);
    //off_t res = file_read(f, fu, (off_t) size);
    //printf("done file");
    /*
    int i;
    int s = (int) size;
    for(i = 0; i < s; i++) {
      printf("i:%d buffer + i: %p\n",i, buffer + i);
      put_user(buffer + i, *(fu + i));
    }
    free(fu);
    */
    lock_release(&file_lock);
    return (int) res;
  }

}



int write(int fd, const void *buffer, unsigned size) {


  /* if( (fd < 1) || (fd > 129) ||  (!addr_valid(buffer)) ||
     !(is_mapped(buffer))  ) {*/
  if( (fd < 1) || (fd > 129)  ) {
    exit(-1);
    }
  // printf("..........fd is %d\n", fd);

  lock_acquire(&file_lock);
  if(fd == 1) {
    //write to console
    putbuf(buffer, size);
    lock_release(&file_lock);
    return size;
  }
  //else get file
  //fd - 2
   struct file *write_loc = thread_current()->files[(fd - 2)];
  if(write_loc == NULL) {
    //no file here
    lock_release(&file_lock);
    return -1;
  } else {
    int res = file_write(write_loc, buffer, size);
    lock_release(&file_lock);
    return res;
  }
  
}

void seek(int fd, unsigned position) {

  lock_acquire(&file_lock);
  file_seek(thread_current()->files[(fd - 2)], position);
  lock_release(&file_lock);
}

unsigned tell(int fd) {

  lock_acquire(&file_lock);
  unsigned res = (unsigned) file_tell(thread_current()->files[(fd - 2)]);
  lock_release(&file_lock);
  return res;
  
}

void close(int fd) {

  if(fd < 2 || fd > 129) {
    exit(-1);
  }
  lock_acquire(&file_lock);
  struct thread *cur = thread_current();
  struct file *f = cur->files[(fd - 2)];
  if( (f != NULL) ) {
    file_close(f);
    cur->files[fd - 2] = NULL;
  }
  lock_release(&file_lock);
}

