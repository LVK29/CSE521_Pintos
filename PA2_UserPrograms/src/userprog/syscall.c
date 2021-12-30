
#include "userprog/syscall.h"
#include "lib/user/syscall.h"
#include <stddef.h>
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include <lib/kernel/stdio.h>
#include <stdarg.h>
#include "devices/shutdown.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "userprog/process.h"
#include "threads/synch.h"

static void syscall_handler(struct intr_frame *);
bool sys_create(const char *file, unsigned initial_size);
int sys_write(int fd, const void *buffer, size_t size);
bool sys_remove (const char *file);
int sys_open (const char *file);
int sys_filesize (int fd);
pid_t sys_exec (const char *cmd_line);
int sys_wait (pid_t pid);
void sys_close(int fd);
void sys_halt();

struct file * get_filename (int fd);
void remove_fd (int fd);
void close_all_files();
static struct lock fd_lock;

void syscall_init(void)
{
  intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init (&fd_lock);
}

static void
isValidAddress(void *cur)
{
  if ((cur) >= PHYS_BASE || (cur) == NULL || pagedir_get_page(thread_current()->pagedir, cur) == NULL)
     exit_sys(-1);
}

static void
syscall_handler(struct intr_frame *f UNUSED)
{
  //printf("*esp = 0x%x\n",(unsigned int *) f->esp);
  //hex_dump(f->esp, f->esp, 256, true);

  //printf("Checking is valid\n");
  isValidAddress(f->esp);
  int syscall_number = *(int *)f->esp;
  void **esp_init = f->esp;
  esp_init++;
  isValidAddress(esp_init);

  switch (syscall_number)
  {
    case SYS_EXEC:
      {
        isValidAddress(esp_init);
        const char *file_name = *esp_init;
        if(pagedir_get_page(thread_current()->pagedir, file_name) == NULL){
          exit_sys(-1);
        }
        pid_t pid = sys_exec(file_name);
        f->eax = pid;
    }
      break;
    case SYS_WAIT:
      {
        isValidAddress(esp_init);
        int pid = *(int *)esp_init;
        int status  = sys_wait(pid);
        f->eax = status;
    }
      break;
    case SYS_WRITE:
      {
        //printf("In SYS_WRITE\n");
        int fd = *(int *)esp_init;
        //printf("fd = %d\n",fd);
        esp_init++;
        isValidAddress(esp_init);
        void *buffer = *esp_init;
        isValidAddress(buffer);
        if(pagedir_get_page(thread_current()->pagedir, buffer) == NULL){
          exit_sys(-1);
        }
        //printf("Buffer has: 0x%x\n",(unsigned int *) buffer);
        esp_init++;
        isValidAddress(esp_init);
        size_t size = *(size_t *)esp_init;
        //printf("Size has: %d\n",size);

        int bytes_written = sys_write(fd, buffer, size);
        f->eax = bytes_written;
        //printf("Bytes written: %d\n", bytes_written);
    }
      break;

    case SYS_EXIT:
      {
        // printf("In SYS_EXIT\n");
        isValidAddress(esp_init);
        int status = *(int *)esp_init;
        f->eax = status;
        exit_sys(status);
      }
      break;

    case SYS_HALT:
      {
        sys_halt();
      }
      break;

    case SYS_CREATE:
      {
        isValidAddress(esp_init);
        const char *file_name = *esp_init;
        if(pagedir_get_page(thread_current()->pagedir, file_name) == NULL){
          exit_sys(-1);
        }
        esp_init++;
        isValidAddress(esp_init);
        unsigned size = *(unsigned *)esp_init;

       bool status = sys_create(file_name, size);
       f->eax = status;
       //printf("Bytes written: %d\n", status);
      }
      break;

    case SYS_REMOVE:
      {
        isValidAddress(esp_init);
        const char *file_name = *esp_init;
        bool status = sys_remove(file_name);
        f->eax = status;
      }
      break;

      case SYS_OPEN:
      {
        isValidAddress(esp_init);
        const char *file_name = *esp_init;
        if(pagedir_get_page(thread_current()->pagedir, file_name) == NULL){
          exit_sys(-1);
        }
        int fd = sys_open(file_name);
        f->eax = fd;
      }
      break;

      case SYS_FILESIZE:
      {
        isValidAddress(esp_init);
        int fd = *(int *)esp_init;
        int size = sys_filesize(fd);
        f->eax = size;
      }
      break;

      case SYS_CLOSE:
      {
        isValidAddress(esp_init);
        int fd = *(int *)esp_init;
        sys_close(fd);
      }
      break;

      case SYS_READ:
      {
        int fd = *(int *)esp_init;
        esp_init++;
        isValidAddress(esp_init);
        void *buffer = *esp_init;
        isValidAddress(buffer);
        if(pagedir_get_page(thread_current()->pagedir, buffer) == NULL){
          exit_sys(-1);
        }
        esp_init++;
        isValidAddress(esp_init);
        size_t size = *(size_t *)esp_init;
        int bytes_read = sys_read(fd, buffer, size);
        f->eax = bytes_read;
      }
      break;

      case SYS_TELL:
      {
        isValidAddress(esp_init);
        int fd = *(int *)esp_init;
        struct file *file_ptr;
        file_ptr=get_filename(fd);       
        unsigned pos = file_tell(file_ptr);
        f->eax = pos;
        break;
      }

      case SYS_SEEK:
      {
        isValidAddress(esp_init);
        int fd = *(int *)esp_init;
        // move esp to file
        esp_init++;
        isValidAddress(esp_init);
        unsigned position = *(unsigned *)esp_init;
        struct file *file_ptr;
        file_ptr=get_filename(fd);       
        file_seek(file_ptr , position);
        break;
      }
  
    default:
      break;
  }
  
}

int sys_write(int fd, const void *buffer, size_t size)
{
  //todo - check max size
  //todo - fd is not valid
  // printf("Size has: %d\n",(int)size);
  struct file *file_ptr = get_filename(fd);
  if(fd==1){
    putbuf(buffer, size);
    return (int)size;
  }
  if(file_ptr==NULL)
  {
    return -1;
  }
  int ret = (int) file_write(file_ptr,buffer,size);
  return ret;
  }

int sys_read(int fd, const void *buffer, size_t size)
{
  struct file *file_ptr;
  file_ptr=get_filename(fd);
  if(file_ptr==NULL)
  {
    return -1;
  }
  if(fd==1)
  {
    exit_sys(-1);
  }
  return (int)file_read(file_ptr,buffer,size);

}

void exit_sys(int status)
{
  printf("%s: exit(%d)\n", thread_current()->name, status);
  if(thread_current()->parent != NULL){ //todo if null & interrupt 
    struct thread *p = thread_current()->parent;

    struct list_elem *e;

    for (e = list_begin (&p->children); e != list_end (&p->children);
      e = list_next (e))
    {
      struct child *c = list_entry (e, struct child, child_elem);
      if(c->tid == thread_current()->tid){
        c->exit_status = status;
        c->has_exited = true;
        if(c->is_waiting){
          sema_up(&p->wait_sema);
        }
        break;
      }
      
    }     
  }
  if(thread_current()->file != NULL) {
    file_close(thread_current()->file);
  }
  close_all_files();

  //free(&thread_current()->children);
  //free(&thread_current()->fd_file_map_list);

  while (!list_empty (&thread_current()->fd_file_map_list))
     {
       struct list_elem *e = list_pop_front (&thread_current()->fd_file_map_list);
       struct fd_file_map *f = list_entry (e, struct fd_file_map, fd_elem);
       free(f);
     }

  while (!list_empty (&thread_current()->children))
     {
       struct list_elem *e = list_pop_front (&thread_current()->children);
       struct child *c = list_entry (e, struct child, child_elem);
       free(c);
     }

  thread_exit();
  //need to close every fd and file
}

void sys_halt()
{
  shutdown_power_off();
}

bool sys_create(const char *file, unsigned initial_size)
{
  if(file == NULL){
    exit_sys(-1); 
  }
  return filesys_create(file, initial_size);
}

bool sys_remove (const char *file)
{
  return filesys_remove(file);
}

int sys_open (const char *file)
{
  if(file == NULL){
    exit_sys(-1);
  }
  struct file * file_ptr = filesys_open (file);
  if(file_ptr == NULL){
    return -1;
  }
  lock_acquire (&fd_lock);
  struct fd_file_map *curr = malloc (sizeof (struct fd_file_map));
  curr->file = file_ptr;
  curr->fd = allocate_fd();
  list_push_back(&thread_current()->fd_file_map_list, &curr->fd_elem); 
  //file_deny_write(file_ptr);
  lock_release (&fd_lock);
  //todo - check memory allocation
  return curr->fd;
  
}

int sys_filesize (int fd)
{
  struct file *file_ptr;
  file_ptr=get_filename(fd);
  return file_length (file_ptr); 
}

void sys_close(int fd){

  struct file *file_ptr;
  file_ptr = get_filename(fd);
  file_close(file_ptr);
  remove_fd(fd);
}

pid_t sys_exec (const char *cmd_line)
{
  pid_t pid = process_execute(cmd_line);
  return pid;
}
int sys_wait (pid_t pid)
{
  int exit = process_wait(pid);
  return exit;
}

void  close_all_files (void)
{
  struct list_elem *e;
  for (e = list_begin (&thread_current()->fd_file_map_list); e != list_end (&thread_current()->fd_file_map_list);
       e = list_next (e))
    {
      struct fd_file_map *f = list_entry (e, struct fd_file_map, fd_elem);
      file_close(f->file);;
    }
}



struct file * get_filename (int fd) {
  struct list_elem *e;
  struct file *file_ptr;
  file_ptr=NULL;
  for (e = list_begin (&thread_current()->fd_file_map_list); e != list_end (&thread_current()->fd_file_map_list);
       e = list_next (e))
    {
      struct fd_file_map *f = list_entry (e, struct fd_file_map, fd_elem);
      if(f->fd == fd){
        file_ptr = f->file;
        break;
      }
    }
    return file_ptr;
}

void remove_fd (int fd) {
  struct list_elem *e;
  struct file *file_ptr;
  for (e = list_begin (&thread_current()->fd_file_map_list); e != list_end (&thread_current()->fd_file_map_list);
       e = list_next (e))
    {
      struct fd_file_map *f = list_entry (e, struct fd_file_map, fd_elem);
      if(f->fd == fd){
        file_ptr = f->file;
        list_remove (e);
        break;
      }
    }
}




