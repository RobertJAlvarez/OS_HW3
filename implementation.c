/*MyFS: a tiny file-system written for educational purposes

  MyFS is 

  Copyright 2018-21 by

  University of Alaska Anchorage, College of Engineering.

  Copyright 2022

  University of Texas at El Paso, Department of Computer Science.

  Contributors: Christoph Lauter
                ... 
                ... and
                ...

  and based on 

  FUSE: Filesystem in Userspace
  Copyright (C) 2001-2007  Miklos Szeredi <miklos@szeredi.hu>

  This program can be distributed under the terms of the GNU GPL.
  See the file COPYING.

  gcc -Wall myfs.c implementation.c alloc.c `pkg-config fuse --cflags --libs` -o myfs
*/

#include <stddef.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include "alloc.h"
#include "implementation.h"

/* The filesystem you implement must support all the 13 operations
   stubbed out below. There need not be support for access rights,
   links, symbolic links. There needs to be support for access and
   modification times and information for statfs.

   The filesystem must run in memory, using the memory of size 
   fssize pointed to by fsptr. The memory comes from mmap and 
   is backed with a file if a backup-file is indicated. When
   the filesystem is unmounted, the memory is written back to 
   that backup-file. When the filesystem is mounted again from
   the backup-file, the same memory appears at the newly mapped
   in virtual address. The filesystem datastructures hence must not
   store any pointer directly to the memory pointed to by fsptr; it
   must rather store offsets from the beginning of the memory region.

   When a filesystem is mounted for the first time, the whole memory
   region of size fssize pointed to by fsptr reads as zero-bytes. When
   a backup-file is used and the filesystem is mounted again, certain
   parts of the memory, which have previously been written, may read
   as non-zero bytes. The size of the memory region is at least 2048
   bytes.

   CAUTION:

   * You MUST NOT use any global variables in your program for reasons
   due to the way FUSE is designed.

   You can find ways to store a structure containing all "global" data
   at the start of the memory region representing the filesystem.

   * You MUST NOT store (the value of) pointers into the memory region
   that represents the filesystem. Pointers are virtual memory
   addresses and these addresses are ephemeral. Everything will seem
   okay UNTIL you remount the filesystem again.

   You may store offsets/indices (of type size_t) into the
   filesystem. These offsets/indices are like pointers: instead of
   storing the pointer, you store how far it is away from the start of
   the memory region. You may want to define a type for your offsets
   and to write two functions that can convert from pointers to
   offsets and vice versa.

   * You may use any function out of libc for your filesystem,
   including (but not limited to) malloc, calloc, free, strdup,
   strlen, strncpy, strchr, strrchr, memset, memcpy. However, your
   filesystem MUST NOT depend on memory outside of the filesystem
   memory region. Only this part of the virtual memory address space
   gets saved into the backup-file. As a matter of course, your FUSE
   process, which implements the filesystem, MUST NOT leak memory: be
   careful in particular not to leak tiny amounts of memory that
   accumulate over time. In a working setup, a FUSE process is
   supposed to run for a long time!

   It is possible to check for memory leaks by running the FUSE
   process inside valgrind:

   valgrind --leak-check=full ./myfs --backupfile=test.myfs ~/fuse-mnt/ -f

   However, the analysis of the leak indications displayed by valgrind
   is difficult as libfuse contains some small memory leaks (which do
   not accumulate over time). We cannot (easily) fix these memory
   leaks inside libfuse.

   * Avoid putting debug messages into the code. You may use fprintf
   for debugging purposes but they should all go away in the final
   version of the code. Using gdb is more professional, though.

   * You MUST NOT fail with exit(1) in case of an error. All the
   functions you have to implement have ways to indicated failure
   cases. Use these, mapping your internal errors intelligently onto
   the POSIX error conditions.

   * And of course: your code MUST NOT SEGFAULT!

   It is reasonable to proceed in the following order:

   (1)   Design and implement a mechanism that initializes a filesystem
         whenever the memory space is fresh. That mechanism can be
         implemented in the form of a filesystem handle into which the
         filesystem raw memory pointer and sizes are translated.
         Check that the filesystem does not get reinitialized at mount
         time if you initialized it once and unmounted it but that all
         pieces of information (in the handle) get read back correctly
         from the backup-file. 

   (2)   Design and implement functions to find and allocate free memory
         regions inside the filesystem memory space. There need to be 
         functions to free these regions again, too. Any "global" variable
         goes into the handle structure the mechanism designed at step (1) 
         provides.

   (3)   Carefully design a data structure able to represent all the
         pieces of information that are needed for files and
         (sub-)directories.  You need to store the location of the
         root directory in a "global" variable that, again, goes into the 
         handle designed at step (1).

   (4)   Write __myfs_getattr_implem and debug it thoroughly, as best as
         you can with a filesystem that is reduced to one
         function. Writing this function will make you write helper
         functions to traverse paths, following the appropriate
         subdirectories inside the file system. Strive for modularity for
         these filesystem traversal functions.

   (5)   Design and implement __myfs_readdir_implem. You cannot test it
         besides by listing your root directory with ls -la and looking
         at the date of last access/modification of the directory (.). 
         Be sure to understand the signature of that function and use
         caution not to provoke segfaults nor to leak memory.

   (6)   Design and implement __myfs_mknod_implem. You can now touch files 
         with 

         touch foo

         and check that they start to exist (with the appropriate
         access/modification times) with ls -la.

   (7)   Design and implement __myfs_mkdir_implem. Test as above.

   (8)   Design and implement __myfs_truncate_implem. You can now 
         create files filled with zeros:

         truncate -s 1024 foo

   (9)   Design and implement __myfs_statfs_implem. Test by running
         df before and after the truncation of a file to various lengths. 
         The free "disk" space must change accordingly.

   (10)  Design, implement and test __myfs_utimens_implem. You can now 
         touch files at different dates (in the past, in the future).

   (11)  Design and implement __myfs_open_implem. The function can 
         only be tested once __myfs_read_implem and __myfs_write_implem are
         implemented.

   (12)  Design, implement and test __myfs_read_implem and
         __myfs_write_implem. You can now write to files and read the data 
         back:

         echo "Hello world" > foo
         echo "Hallo ihr da" >> foo
         cat foo

         Be sure to test the case when you unmount and remount the
         filesystem: the files must still be there, contain the same
         information and have the same access and/or modification
         times.

   (13)  Design, implement and test __myfs_unlink_implem. You can now
         remove files.

   (14)  Design, implement and test __myfs_unlink_implem. You can now
         remove directories.

   (15)  Design, implement and test __myfs_rename_implem. This function
         is extremely complicated to implement. Be sure to cover all 
         cases that are documented in man 2 rename. The case when the 
         new path exists already is really hard to implement. Be sure to 
         never leave the filessystem in a bad state! Test thoroughly 
         using mv on (filled and empty) directories and files onto 
         inexistant and already existing directories and files.

   (16)  Design, implement and test any function that your instructor
         might have left out from this list. There are 13 functions 
         __myfs_XXX_implem you have to write.

   (17)  Go over all functions again, testing them one-by-one, trying
         to exercise all special conditions (error conditions): set
         breakpoints in gdb and use a sequence of bash commands inside
         your mounted filesystem to trigger these special cases. Be
         sure to cover all funny cases that arise when the filesystem
         is full but files are supposed to get written to or truncated
         to longer length. There must not be any segfault; the user
         space program using your filesystem just has to report an
         error. Also be sure to unmount and remount your filesystem,
         in order to be sure that it contents do not change by
         unmounting and remounting. Try to mount two of your
         filesystems at different places and copy and move (rename!)
         (heavy) files (your favorite movie or song, an image of a cat
         etc.) from one mount-point to the other. None of the two FUSE
         processes must provoke errors. Find ways to test the case
         when files have holes as the process that wrote them seeked
         beyond the end of the file several times. Your filesystem must
         support these operations at least by making the holes explicit 
         zeros (use dd to test this aspect).

   (18)  Run some heavy testing: copy your favorite movie into your
         filesystem and try to watch it out of the filesystem.
*/

/* START __malloc_impl, realloc_impl, free_impl */

// BEGINNING OF STRUCTS

typedef struct s_AllocateFrom {
  size_t remaining;
  struct s_AllocateFrom *next_space;
} AllocateFrom;

typedef struct s_List {
  struct s_AllocateFrom *first_space;
} List;

// END OF STRUCTS

// BEGINNING OF HELPER FUNCTIONS DECLARATION

/* Make an AllocateFrom item using length and start and add it to the list which does it in ascending order. */
static void add_allocation_space(List *LL, AllocateFrom *new_space);

/*
 */
static void *get_allocation(List *LL, size_t size);

// END OF HELPER FUNCTIONS DECLARATION

/* Make an AllocateFrom item using length and start and add it to the list which does it in ascending order */
static void add_allocation_space(List *LL, AllocateFrom *alloc)
{
  AllocateFrom *temp = LL->first_space;

  //new_space address is less than the first_space in LL
  if (temp > alloc) {
    /* At this point we know that alloc comes before LL->first_space */
    LL->first_space = alloc; //Update first space
    //Check if we can merge LL->first_space and alloc
    if ( (((char *) alloc) + sizeof(size_t) + alloc->remaining) == ((char *) temp) ) {
      //Combine the spaces available
      alloc->remaining += sizeof(size_t) + temp->remaining;
      //Update pointers
      alloc->next_space = temp->next_space;
    }
    //We couldn't merge so we just add it as the first_space and update pointers
    else {
      alloc->next_space = temp;
    }
  }
  //Find after what pointer does alloc should be added
  else {
    //Get the last pointer that is in lower memory than alloc
    while ( (temp->next_space != NULL) && (temp->next_space < alloc) ) {
      temp = temp->next_space;
    }
    /* Merge alloc and the space after alloc */
    //At this point, temp is before alloc and alloc is before temp->next_space. But, there is no guaranty that temp->next_space != NULL
    AllocateFrom *after_alloc = temp->next_space;
    if (after_alloc != NULL) {
      //Check if we can merge alloc and after_alloc
      if ( (((char *) alloc) + sizeof(size_t) + alloc->remaining) == ((char *) after_alloc) ) {
        alloc->remaining += sizeof(size_t) + after_alloc->remaining;
        alloc->next_space = after_alloc->next_space;
      }
      //We couldn't merge them
      else {
        alloc->next_space = after_alloc;
      }
    }
    //alloc is the last space available in memory ascending order
    else {
      alloc->next_space = NULL;
    }
    /* Merge temp (which is before alloc) and alloc */
    if ( (((char *) temp) + sizeof(size_t) + temp->remaining) == ((char *) alloc) ) {
      temp->remaining += sizeof(size_t) + alloc->remaining;
      temp->next_space = alloc->next_space;
    }
    //We couldn't merge them
    else {
      temp->next_space = alloc;
    }
  }
}

static void *get_allocation(List *LL, size_t size)
{
  AllocateFrom *alloc = LL->first_space;
  AllocateFrom *ptr = NULL;

  //If the first page have just enough space from the first_space in our LL
  if ( (alloc->remaining >= size) && (alloc->remaining < (size+sizeof(AllocateFrom))) ) {
    //Everything on the first space is taken so now LL point to the second space to use the first one
    LL->first_space = alloc->next_space;
    //Get ptr to point to the beginning of the first space to return it
    ptr = alloc;
  }
  //If the first block have more space that what is asked for and it can create another AllocateFrom object without issues
  else if (alloc->remaining > size) {
    //LL is now pointing to what is remaining after using size
    LL->first_space = (AllocateFrom *) (((void *) alloc) + sizeof(size_t) + size);
    //Same pointer to second page but now on the new first_space
    LL->first_space->next_space = alloc->next_space;
    //Update the remaining space in first_space after using size
    LL->first_space->remaining = alloc->remaining - size - sizeof(size_t);
    //Update new value of alloc, which is size
    alloc->remaining = size;
    //Get ptr to point to the beginning of the previous first space
    ptr = alloc;
  }
  //If the first page don't have enough space for what was asked
  else {
    //TODO: If no block can hold what is needed, we save the largest block found

    //Find a node that is pointing to an space where we can get size from
    while ( (alloc->next_space != NULL) && (alloc->next_space->remaining < size) ) {
      alloc = alloc->next_space;
    }

    //TODO: Check if we got everything or just a portion
    if (alloc->next_space == NULL) {
      //
    }
    //If we find a valid space to get memory from
    else {
      //Save the space in memory that is going to be returned
      ptr = alloc->next_space;
      //If ptr have just enough space to hold size
      if ( (ptr->remaining >= size) && (ptr->remaining < (size+sizeof(AllocateFrom))) ) {
        //Everything on ptr is taken so now alloc points to what is after ptr
        alloc->next_space = ptr->next_space;
      }
      //If ptr have enough space to hold size and create another AllocateFrom object
      else {
        //alloc is now pointing to what is remaining after using size from ptr
        alloc->next_space = (AllocateFrom *) (((void *) ptr) + sizeof(size_t) + size);
        //What is after alloc is now pointing to what ptr was pointing at
        alloc->next_space->next_space = ptr->next_space;
        //Update the remaining space in what is after alloc after using size
        alloc->next_space->remaining = ptr->remaining - size - sizeof(size_t);
        //Update ptr new remaining which is what it was asked for
        ptr->remaining = size;
      }
    }
  }

  //Adjust ptr to not overwrite remaining variable with the number of bytes passed
  return ((char *) ptr) + sizeof(size_t);
}

/* If size is zero, return NULL. Otherwise, call get_allocation_space with size. */
void *__malloc_impl(List *LL, size_t size)
{
  if (size == ((size_t) 0)) {
    return NULL;
  }

  return get_allocation(LL, size);
}

/* If size is less than what already assign to *ptr just lock what is after size and add it using add_allocation_space. */
void *__realloc_impl(List *LL, void *ptr, size_t size)
{
  //If size is 0, we free the ptr and return NULL
  if (size == ((size_t) 0)) {
    __free_impl(LL, ptr);
    return NULL;
  }

  //If ptr is NULL, realloc() is identical to a call to malloc() for size bytes.
  if (ptr == NULL) {
    return get_allocation(LL, size);
  }

  AllocateFrom *alloc = (AllocateFrom *) (((void *) ptr) - sizeof(size_t));
  AllocateFrom *temp;

  //If the new size is less than before but not enough to make an AllocateFrom object
  if ( (alloc->remaining >= size) && (alloc->remaining < (size + sizeof(AllocateFrom))) ) {
    return ptr;
  }
  //If the new size is less than before and we can create an AllocateFrom element to add to LL
  else if (alloc->remaining > size) {
    //Save what is left in temp and add it to the LL
    temp = (AllocateFrom *) (((void *) alloc) + sizeof(size_t) + size);
    temp->remaining = alloc->remaining - sizeof(size_t) - size;
    temp->next_space = NULL;
    add_allocation_space(LL, temp);
    //Update remaining space
    alloc->remaining = size;
  }
  //If we are asking for more than what we have in alloc
  else {
    //Get new space to copy to
    void *new_ptr = get_allocation(LL, size);
    //We couldn't get enough space
    if (new_ptr == NULL) {
      return NULL;
    }
    //Copy space where to copy to, so we can iterate without losing the beginning
    memcpy(new_ptr, ptr, alloc->remaining);
    //Put alloc back into the LL for reuse
    add_allocation_space(LL, alloc);
  }

  return ptr;
}

/* Add space back to List using add_allocation_space */
void __free_impl(List *LL, void *ptr)
{
  if (ptr == NULL) {
    return;
  }

  //Adjust ptr so size_t before to start on the size of pointer
  AllocateFrom *temp = (AllocateFrom *) (ptr - sizeof(size_t));
  add_allocation_space(LL, temp);
}

/* END __malloc_impl, realloc_impl, free_impl */

/* START of FUSE implementation */

/* HELPER TYPES AND STRUCTS GO HERE */
#define MYFS_MAGIC ((uint32_t) 0xCAFEBABE)
#define NAME_MAX_LEN ((size_t) 255)

typedef size_t __off_t;
typedef unsigned int u_int;

typedef struct __handler_t {
  uint32_t magic;
  __off_t root_dir;
  __off_t free_memory;
  size_t size;
} handler_t;

typedef struct __free_block_t {
  size_t size;
  __off_t next_block;
} free_block_t;

typedef struct __file_block_t {
  size_t size;
  size_t allocated;
  __off_t data;
  __off_t next_file_block;
} file_block_t;

typedef struct __inode_file_t {
  size_t total_size;
  __off_t first_file_block;  //This is an offset to the first file_block_t
} file_t;

typedef struct __inode_directory_t {
  //Max number of children is given at the children array location - sizeof() divided by the sizeof(node_t *)
  //This time the header of the block of memory is exclusive of the sizeof(size_t)
  size_t number_children;
  //children is an offset to an array of offsets to folders and files. Children starts with '..' offsets
  __off_t children;
} directory_t;

typedef struct __times_t {
  u_int second : 5;  //Do << 1 for a range max of 62
  u_int minute : 6;  //0 < minutes < 63
  u_int hour : 5;    //0 < hour < 31
  u_int day : 5;     //0 < day < 31
  u_int month : 4;   //0 < month < 15
  u_int year : 7;    //1970 < year < 1970 + 127 = 2107
} my_time;

typedef struct __inode_t {
  char name[NAME_MAX_LEN + ((size_t) 1)];
  char is_file;
  my_time times[2]; //times[0]: creation date, times[1]: last modification date
  union {
    file_t file;
    directory_t directory;
  } type;
} node_t;

/* End of types and structs */

/* YOUR HELPER FUNCTIONS GO HERE */
void *off_to_pointer(void *reference, __off_t offset)
{
  void *ptr = reference + offset;

  //Check that our pointer address didn't overflow
  if (ptr < reference) {
    return NULL;
  }

  return ptr;
}

__off_t pointer_to_off(void *reference, void *ptr)
{
  __off_t offset = ((__off_t) (ptr - reference));

  //Check that our offset didn't overflow
  if (((void *) offset) < reference) {
    return 0;
  }

  return offset;
}

void set_time(struct tm *timeinfo, my_time *t)
{
  t->second = ((u_int) timeinfo->tm_sec >> 1);
  t->minute = ((u_int) timeinfo->tm_min);
  t->hour = ((u_int) timeinfo->tm_hour);
  t->day = ((u_int) timeinfo->tm_mday);
  t->month = ((u_int) timeinfo->tm_mon);
  t->year = ((u_int) timeinfo->tm_year);
}

void update_time(node_t *node, int new_node)
{
  if (node == NULL) {
    return;
  }

  time_t ts;
  struct tm *timeinfo;

  time(&ts);
  timeinfo = localtime(&ts);

  //TODO: Check for errors
  if (1) {
    //Update last modification
    set_time(timeinfo, &node->times[1]);
    //Check if date of creation needs to be set
    if (new_node) {
      set_time(timeinfo, &node->times[0]);
    }
  }
}

void make_dir_node(void *fsptr, node_t *node, const char *name, size_t max_chld, __off_t parent_off_t)
{
  memset(node->name, '\0', NAME_MAX_LEN + ((size_t) 1));  //File all name characters to '\0'
  memcpy(node->name, name, strlen(name)); //Copy given name into node->name
  node->is_file = 0;
  update_time(node, 1);
  directory_t dict = node->type.directory;
  dict.max_children = max_chld;         //We currently only have space allocated to hold 4 nodes
  dict.number_children = ((size_t) 1);  //We use the first child space for '..'

  //Get linked list pointer header
  List *LL = off_to_pointer(fsptr, ((handler_t *) fsptr)->free_memory);
  //Call __malloc_impl() to get enough space for max_chld
  __off_t *ptr = ((__off_t *) __malloc_impl(LL, max_chld*sizeof(__off_t)));
  //Save the offset to get to the children
  dict.children = pointer_to_off(fsptr, ptr);
  //Set first children to point to its parent
  *ptr = parent_off_t;
}

void handler(void *fsptr, size_t fssize)
{
  handler_t *handle = ((handler_t *) fsptr);

  //If we are mounting the file system for the first time
  if (handle->magic != MYFS_MAGIC) {
    //Set general stats
    handle->magic = MYFS_MAGIC;
    handle->size = fssize;

    //Save space for root directory
    //root directory is a node_t variable that starts after the handler_t object at the beginning of our file system
    handle->root_dir = sizeof(handler_t);     //Only store the offset
    node_t *root = off_to_pointer(fsptr, handle->root_dir);

    //Set the free blocks information
    //We had use a handler_t and a node_t for the root directory
    handle->free_memory = handle->root_dir + sizeof(node_t);  //This is just the offset
    free_block_t *fb = off_to_pointer(fsptr, handle->free_memory);

    //Set everything on memory to be 0 starting at the first free block + sizeof(size_t)
    fb->size = fssize - handle->free_memory;
    memset(((void *) fb) + sizeof(size_t), 0, fb->size - sizeof(size_t));
    fb->next_block = NULL;

    //Set the root directory to be name '/' with 4 children where the parent is NULL
    make_dir_node(fsptr, root, "/", 4, 0);
  }
}

char **tokenize(const char token, const char *path)
{
  u_int n_tokens = 0;
  for (const char *c = path; *c != '\0'; c++) {
    if (*c == token) {
      n_tokens++;
    }
  }

  char **tokens = (char **) malloc((n_tokens+1)*sizeof(char *));
  const char *start = &path[1];  //Jump the first character which is '\'
  const char *end = start;
  char *t;

  //Populate tokens
  for (u_int i = 0; i < n_tokens; i++) {
    while ( (*end != token) && (*end != '\0') ) {
      end++;
    }
    //Make space for the token
    t = (char *) malloc((((u_int) (end-start))+((u_int)1))*sizeof(char));
    //Copy token
    memcpy(t, start, end-start);
    t[end-start] = '\0';
    tokens[i] = t;
    start = ++end;
  }
  //Make array a null terminated
  tokens[n_tokens] = NULL;

  return tokens;
}

void print_tokens(char **tokens)
{
  for ( ; *tokens; tokens++) {
    printf("%s\n", *tokens);
  }
}

node_t *path_solver(void *fsptr, const char *path, int *errnoptr)
{
  char **tokens = tokenize('/', path);

  return NULL;
}
/* End of helper functions */

/* Implements an emulation of the stat system call on the filesystem 
   of size fssize pointed to by fsptr. 

   If path can be followed and describes a file or directory 
   that exists and is accessable, the access information is 
   put into stbuf. 

   On success, 0 is returned. On failure, -1 is returned and 
   the appropriate error code is put into *errnoptr.

   man 2 stat documents all possible error codes and gives more detail
   on what fields of stbuf need to be filled in. Essentially, only the
   following fields need to be supported:

   st_uid      the value passed in argument
   st_gid      the value passed in argument
   st_mode     (as fixed values S_IFDIR | 0755 for directories,
                                S_IFREG | 0755 for files)
   st_nlink    (as many as there are subdirectories (not files) for directories
                (including . and ..),
                1 for files)
   st_size     (supported only for files, where it is the real file size)
   st_atim
   st_mtim
*/
int __myfs_getattr_implem(void *fsptr, size_t fssize, int *errnoptr, uid_t uid, gid_t gid, const char *path, struct stat *stbuf)
{
  /* STUB */
  return -1;
}

/* Implements an emulation of the readdir system call on the filesystem 
   of size fssize pointed to by fsptr. 

   If path can be followed and describes a directory that exists and
   is accessable, the names of the subdirectories and files 
   contained in that directory are output into *namesptr. The . and ..
   directories must not be included in that listing.

   If it needs to output file and subdirectory names, the function
   starts by allocating (with calloc) an array of pointers to
   characters of the right size (n entries for n names). Sets
   *namesptr to that pointer. It then goes over all entries
   in that array and allocates, for each of them an array of
   characters of the right size (to hold the i-th name, together 
   with the appropriate '\0' terminator). It puts the pointer
   into that i-th array entry and fills the allocated array
   of characters with the appropriate name. The calling function
   will call free on each of the entries of *namesptr and 
   on *namesptr.

   The function returns the number of names that have been 
   put into namesptr. 

   If no name needs to be reported because the directory does
   not contain any file or subdirectory besides . and .., 0 is 
   returned and no allocation takes place.

   On failure, -1 is returned and the *errnoptr is set to 
   the appropriate error code. 

   The error codes are documented in man 2 readdir.

   In the case memory allocation with malloc/calloc fails, failure is
   indicated by returning -1 and setting *errnoptr to EINVAL.
*/
int __myfs_readdir_implem(void *fsptr, size_t fssize, int *errnoptr, const char *path, char ***namesptr)
{
  /* STUB */
  return -1;
}

/* Implements an emulation of the mknod system call for regular files
   on the filesystem of size fssize pointed to by fsptr.

   This function is called only for the creation of regular files.

   If a file gets created, it is of size zero and has default
   ownership and mode bits.

   The call creates the file indicated by path.

   On success, 0 is returned.

   On failure, -1 is returned and *errnoptr is set appropriately.

   The error codes are documented in man 2 mknod.
*/
int __myfs_mknod_implem(void *fsptr, size_t fssize, int *errnoptr, const char *path)
{
  /* STUB */
  return -1;
}

/* Implements an emulation of the unlink system call for regular files
   on the filesystem of size fssize pointed to by fsptr.

   This function is called only for the deletion of regular files.

   On success, 0 is returned.

   On failure, -1 is returned and *errnoptr is set appropriately.

   The error codes are documented in man 2 unlink.
*/
int __myfs_unlink_implem(void *fsptr, size_t fssize, int *errnoptr, const char *path)
{
  node_t *node = path_solver(fsptr, path, errnoptr);

  if(node == NULL){
    *errnoptr = ENOENT;
    return -1;
  }

  for (int i = 0; i < sizeof(node->name); i++){
    //Check if the next char in the name is null character
    if(node->name[i+1] == "\0"){
      *errnoptr = EISDIR;
      return -1;
    }
    //Check that the name does not have a forward slash
    if(node->name[i] == "/"){
      *errnoptr = EISDIR;
      return -1;
    }
    //Check that the name is not greated than 256
    if(node->name[i] == " " && node->name[i+1] == " "){

      //Update number of children for directory
      node->type.directory.number_children--;

      //Update last time of modification
      update_time(node, 1);
    }
  }
  return 0;
}

/* Implements an emulation of the rmdir system call on the filesystem 
   of size fssize pointed to by fsptr. 

   The call deletes the directory indicated by path.

   On success, 0 is returned.

   On failure, -1 is returned and *errnoptr is set appropriately.

   The function call must fail when the directory indicated by path is
   not empty (if there are files or subdirectories other than . and ..).

   The error codes are documented in man 2 rmdir.
*/
int __myfs_rmdir_implem(void *fsptr, size_t fssize, int *errnoptr, const char *path)
{
  node_t *node = path_solver(fsptr, path, errnoptr);

  if (node == NULL){
    *errnoptr = ENOENT;
    return -1;
  }

  for (int i = 0; i < sizeof(node->name); i++){
    //Check if the next char in the name is null character
    if (node->name[i+1] == "\0"){
      *errnoptr = EISDIR;
      return -1;
    }
    //Check that the name does not have a forward slash
    if (node->name[i] == "/"){
      *errnoptr = EISDIR;
      return -1;
    }
    if (node->name[i] == "." || (node->name[i] == "." && node->name[i+1] == ".")){
      //TODO: CHANGE ERROR POINTER
      return -1;
    }
    //Check that the name is not greated than 256
    if (node->name[i] == " " && node->name[i+1] == " ") {
      //Update number of children for directory
      if (node->type.directory.number_children != 0){
        *errnoptr = ENOTEMPTY;
        return -1;
      }
    }
  }
  return 0;
}

/* Implements an emulation of the mkdir system call on the filesystem 
   of size fssize pointed to by fsptr. 

   The call creates the directory indicated by path.

   On success, 0 is returned.

   On failure, -1 is returned and *errnoptr is set appropriately.

   The error codes are documented in man 2 mkdir.
*/

int __myfs_mkdir_implem(void *fsptr, size_t fssize, int *errnoptr, const char *path)
{
  /* STUB */
  return -1;
}

/* Implements an emulation of the rename system call on the filesystem 
   of size fssize pointed to by fsptr. 

   The call moves the file or directory indicated by from to to.

   On success, 0 is returned.

   On failure, -1 is returned and *errnoptr is set appropriately.

   Caution: the function does more than what is hinted to by its name.
   In cases the from and to paths differ, the file is moved out of 
   the from path and added to the to path.

   The error codes are documented in man 2 rename.
*/
int __myfs_rename_implem(void *fsptr, size_t fssize, int *errnoptr, const char *from, const char *to)
{
  /* STUB */
  return -1;
}

/* Implements an emulation of the truncate system call on the filesystem 
   of size fssize pointed to by fsptr. 

   The call changes the size of the file indicated by path to offset
   bytes.

   When the file becomes smaller due to the call, the extending bytes are
   removed. When it becomes larger, zeros are appended.

   On success, 0 is returned.

   On failure, -1 is returned and *errnoptr is set appropriately.

   The error codes are documented in man 2 truncate.
*/
int __myfs_truncate_implem(void *fsptr, size_t fssize, int *errnoptr, const char *path, off_t offset)
{
  /* STUB */
  return -1;
}

/* Implements an emulation of the open system call on the filesystem 
   of size fssize pointed to by fsptr, without actually performing the opening
   of the file (no file descriptor is returned).

   The call just checks if the file (or directory) indicated by path
   can be accessed, i.e. if the path can be followed to an existing
   object for which the access rights are granted.

   On success, 0 is returned.

   On failure, -1 is returned and *errnoptr is set appropriately.

   The two only interesting error codes are 

   * EFAULT: the filesystem is in a bad state, we can't do anything

   * ENOENT: the file that we are supposed to open doesn't exist (or a
             subpath).

   It is possible to restrict ourselves to only these two error
   conditions. It is also possible to implement more detailed error
   condition answers.

   The error codes are documented in man 2 open.
*/
int __myfs_open_implem(void *fsptr, size_t fssize, int *errnoptr, const char *path)
{
  node_t *node = path_solver(fsptr, path, errnoptr);

  // Checks if path is valid, if not valid return -1
  if (node == NULL) {
    return -1;
  }

  //Checks if node is a file, if it is a file return 0
  return node->is_file ? 0 : -1;
}

/* Implements an emulation of the read system call on the filesystem 
   of size fssize pointed to by fsptr.

   The call copies up to size bytes from the file indicated by 
   path into the buffer, starting to read at offset. See the man page
   for read for the details when offset is beyond the end of the file etc.
   
   On success, the appropriate number of bytes read into the buffer is
   returned. The value zero is returned on an end-of-file condition.

   On failure, -1 is returned and *errnoptr is set appropriately.

   The error codes are documented in man 2 read.
*/
int __myfs_read_implem(void *fsptr, size_t fssize, int *errnoptr, const char *path, char *buf, size_t size, off_t offset)
{
  /* STUB */
  return -1;
}

/* Implements an emulation of the write system call on the filesystem 
   of size fssize pointed to by fsptr.

   The call copies up to size bytes to the file indicated by 
   path into the buffer, starting to write at offset. See the man page
   for write for the details when offset is beyond the end of the file etc.
   
   On success, the appropriate number of bytes written into the file is
   returned. The value zero is returned on an end-of-file condition.

   On failure, -1 is returned and *errnoptr is set appropriately.

   The error codes are documented in man 2 write.
*/
int __myfs_write_implem(void *fsptr, size_t fssize, int *errnoptr, const char *path, const char *buf, size_t size, off_t offset)
{
  /* STUB */
  return -1;
}

/* Implements an emulation of the utimensat system call on the filesystem 
   of size fssize pointed to by fsptr.

   The call changes the access and modification times of the file
   or directory indicated by path to the values in ts.

   On success, 0 is returned.

   On failure, -1 is returned and *errnoptr is set appropriately.

   The error codes are documented in man 2 utimensat.
*/
int __myfs_utimens_implem(void *fsptr, size_t fssize, int *errnoptr, const char *path, const struct timespec ts[2])
{
  /* STUB */
  return -1;
}

/* Implements an emulation of the statfs system call on the filesystem 
   of size fssize pointed to by fsptr.

   The call gets information of the filesystem usage and puts in 
   into stbuf.

   On success, 0 is returned.

   On failure, -1 is returned and *errnoptr is set appropriately.

   The error codes are documented in man 2 statfs.

   Essentially, only the following fields of struct statvfs need to be
   supported:

   f_bsize   fill with what you call a block (typically 1024 bytes)
   f_blocks  fill with the total number of blocks in the filesystem
   f_bfree   fill with the free number of blocks in the filesystem
   f_bavail  fill with same value as f_bfree
   f_namemax fill with your maximum file/directory name, if your
             filesystem has such a maximum
*/
int __myfs_statfs_implem(void *fsptr, size_t fssize, int *errnoptr, struct statvfs* stbuf)
{
  /* STUB */
  return -1;
}

/* END of FUSE implementation */

