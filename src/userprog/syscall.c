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

static void syscall_handler (struct intr_frame *);

static struct lock file_lock;


tid_t exec(const char *cmd_line);
bool create(const char *file, unsigned initial_size);
bool remove(const char *file);
void seek(int fd, unsigned position);
unsigned tell(int fd);
void close(int fd);

bool is_mapped(int *esp);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init(&file_lock);
}

bool addr_valid(int *esp) {
  //printf("checking %x\n", esp);
  return (esp != NULL)  &&  (is_user_vaddr(esp)) ;
}

bool is_mapped(int *esp) {
  
  int *e = (int *) pagedir_get_page(thread_current()->pagedir, esp);
  return ( e != NULL );
}


int *arg(int *esp, int num) {

  
  int *res = NULL;
  int *t = esp;
  t += num;
  if(!addr_valid(t)) {
    exit(-1);
  }
  res = (int *) pagedir_get_page(thread_current()->pagedir, t);
  ASSERT (is_kernel_vaddr(res));
  return res;
  
}


static void
syscall_handler (struct intr_frame *f) 
{

  // printf("START DDDDDDDDDDDDDDDDDDDDDDDDDDDDDd");
  int *a = f->esp;

  //do validity check
  if( !(is_mapped(a) && addr_valid(a) )  ) {
    //kill? exit?
    //printf("bad esp\n");
    exit(-1);
    
  } else {
    //printf("valid address, esp: %x, points to %d\n", a, *a);
  }

  //printf("This thread is %s\n", thread_current()->name);

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
      //get_args(a, 1, args);
      //open(*args[0]);
      f->eax = open(*arg(a, 1));
      break;
    case SYS_FILESIZE :
      f->eax = filesize(*arg(a, 1));
      break;
    case SYS_READ :
      f->eax = read(*arg(a, 1), *arg(a, 2), *arg(a, 3));
      //printf("in feax: %d\n", f->eax);
      break;
    case SYS_WRITE :
      //  printf("w fd: %x\n", *arg(a, 1));
      //printf("w buf loc: %x\n", *arg(a, 2));
      // printf("w size: %x\n", *arg(a, 3));
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
  

  
  //printf ("system call!\n");
  // thread_exit ();
  

}

void halt() {

  shutdown_power_off();

}

struct exit_status *get_es(struct thread *t) {

  struct exit_status *res = NULL;
  struct thread *par = thread_current()->parent;
  struct list_elem *e = list_begin(&par->children);
  while(e != list_end(&par->children)) {
    struct exit_status *es = list_entry(e, struct exit_status, elem);
    if(es->t == t) {
      res = es;
      break;
    }
    e = list_next(e);
  }

}



void exit(int status) {
  
  //printf("status: %d\n", status);
  struct thread *cur = thread_current();
  if(cur->parent != NULL) {
    struct exit_status *es = get_es(cur);
    es->status = status;
    cur->exit_status = status;
    sema_up(&cur->parent->wait_sem);
    //printf("par is %s, wait sem val: %d\n", cur->parent->name, cur->parent->wait_sem.value);
  }
  //printf("remove\n");
  //REMOVE PARENT FROM CHILDREN
  struct list_elem *e = NULL;
  while(!list_empty(&cur->children)) {
    //printf("clearing children\n");
    struct list_elem *e = list_pop_front(&cur->children);
    struct exit_status *es = list_entry(e, struct exit_status, elem);
    es->t->parent = NULL;
    //free(es);
  }
  //printf("%s: exit(%d)\n", cur->name_only, cur->exit_status);
  
  thread_exit();
}

tid_t exec(const char *cmd_line) {

  //check for load to be finished????
  tid_t res = process_execute(cmd_line);

  //sema_down(&thread_current()->exec_sem);
  //printf("exec sem down\n");
  return res;
  
}


int wait(tid_t pid) {

  return process_wait(pid);
  
  
}

bool create(const char *file, unsigned initial_size) {

  // printf("START CREATE\n");
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

  /*
  printf("called by %s, tid: %d\n", thread_current()->name, thread_current()->tid);
  printf("reached open syscall\n");
  printf("filename: %s\n", file);
  */
  if(!is_mapped(file)) {
    exit(-1);
    
  }
  lock_acquire(&file_lock);
  struct file *f = filesys_open(file);
  if(f == NULL) {
    //printf("no file found\n");
    lock_release(&file_lock);
    return -1;
  }
  //printf("file was FOUND\n");
  int res = add_file(f);
  lock_release(&file_lock);
  // printf("fd is: %d\n", res);
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



  if( (fd < 0) || (fd == 1) ||  (fd > 129) ||
      (!addr_valid(buffer)) || !(is_mapped(buffer))  ) {
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
  //printf("size: %d GOT FILEEEEEEEEEEEEEEEEEEEEEEEEEEe\n", size);
  //printf("read, fd is: %d\n", fd);
  if(f == NULL) {
    lock_release(&file_lock);
    return -1;
  } else {
    off_t res = file_read(f, buffer, (off_t) size);
    //printf("bytes read: %d\n", res);
    lock_release(&file_lock);
    return (int) res;
  }


}


int write(int fd, const void *buffer, unsigned size) {

  if( (fd < 1) || (fd > 129) ||  (!addr_valid(buffer)) || !(is_mapped(buffer)) ) {
    exit(-1);
  }

  lock_acquire(&file_lock);
  //printf("fd is: %d\n", fd);
  if(fd == 1) {
    //write to console
    putbuf(buffer, size);
    lock_release(&file_lock);
    return size;
  }
  //else get file
  //fd - 1
  struct file *write_loc = thread_current()->files[(fd - 2)];
  if(write_loc == NULL) {
    //printf("NO FILE HERE\n");
    lock_release(&file_lock);
    return -1;
  } else {
    int res = file_write(write_loc, buffer, size);
    lock_release(&file_lock);
    return res;
  }
  
  // putbuf("dummy\n", size);
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

//NOTE; CLOSE ALL FILES WHEN PROCESS IS KILLED
void close(int fd) {

  //printf("running close with fd: %d\n", fd);
  if(fd < 2 || fd > 129) {
    exit(-1);
  }
  lock_acquire(&file_lock);
  struct thread *cur = thread_current();
  struct file *f = cur->files[(fd - 2)];
  if(f != NULL) {
    file_close(f);
    cur->files[fd - 2] = NULL;
  }
  lock_release(&file_lock);
}

