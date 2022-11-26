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

  gcc -Wall myfs.c implementation.c `pkg-config fuse --cflags --libs` -o myfs
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
#include "implementation.h"

/* The filesystem you implement must support all the 13 operations stubbed out below. There need not be support for access rights,
   links, symbolic links. There needs to be support for access and modification times and information for statfs.

   The filesystem must run in memory, using the memory of size fssize pointed to by fsptr. The memory comes from mmap and 
   is backed with a file if a backup-file is indicated. When the filesystem is unmounted, the memory is written back to 
   that backup-file. When the filesystem is mounted again from the backup-file, the same memory appears at the newly mapped
   in virtual address. The filesystem datastructures hence must not store any pointer directly to the memory pointed to by fsptr; it
   must rather store offsets from the beginning of the memory region.

   When a filesystem is mounted for the first time, the whole memory region of size fssize pointed to by fsptr reads as zero-bytes. When
   a backup-file is used and the filesystem is mounted again, certain parts of the memory, which have previously been written, may read
   as non-zero bytes. The size of the memory region is at least 2048 bytes.

   CAUTION:

   * You MUST NOT use any global variables in your program for reasons due to the way FUSE is designed.

   You can find ways to store a structure containing all "global" data at the start of the memory region representing the filesystem.

   * You MUST NOT store (the value of) pointers into the memory region that represents the filesystem. Pointers are virtual memory
   addresses and these addresses are ephemeral. Everything will seem okay UNTIL you remount the filesystem again.

   You may store offsets/indices (of type size_t) into the filesystem. These offsets/indices are like pointers: instead of
   storing the pointer, you store how far it is away from the start of the memory region. You may want to define a type for your offsets
   and to write two functions that can convert from pointers to offsets and vice versa.

   * You may use any function out of libc for your filesystem, including (but not limited to) malloc, calloc, free, strdup,
   strlen, strncpy, strchr, strrchr, memset, memcpy. However, your filesystem MUST NOT depend on memory outside of the filesystem
   memory region. Only this part of the virtual memory address space gets saved into the backup-file. As a matter of course, your FUSE
   process, which implements the filesystem, MUST NOT leak memory: be careful in particular not to leak tiny amounts of memory that
   accumulate over time. In a working setup, a FUSE process is supposed to run for a long time!

   It is possible to check for memory leaks by running the FUSE process inside valgrind:

   valgrind --leak-check=full ./myfs --backupfile=test.myfs ~/fuse-mnt/ -f

   However, the analysis of the leak indications displayed by valgrind is difficult as libfuse contains some small memory leaks (which do
   not accumulate over time). We cannot (easily) fix these memory leaks inside libfuse.

   * Avoid putting debug messages into the code. You may use fprintf for debugging purposes but they should all go away in the final
   version of the code. Using gdb is more professional, though.

   * You MUST NOT fail with exit(1) in case of an error. All the functions you have to implement have ways to indicated failure
   cases. Use these, mapping your internal errors intelligently onto the POSIX error conditions.

   * And of course: your code MUST NOT SEGFAULT!

   It is reasonable to proceed in the following order:

   (1)   Design and implement a mechanism that initializes a filesystem whenever the memory space is fresh. That mechanism can be
         implemented in the form of a filesystem handle into which the filesystem raw memory pointer and sizes are translated.
         Check that the filesystem does not get reinitialized at mount time if you initialized it once and unmounted it but that all
         pieces of information (in the handle) get read back correctly from the backup-file. 

   (2)   Design and implement functions to find and allocate free memory regions inside the filesystem memory space. There need to be 
         functions to free these regions again, too. Any "global" variable goes into the handle structure the mechanism designed at step (1) 
         provides.

   (3)   Carefully design a data structure able to represent all the pieces of information that are needed for files and
         (sub-)directories.  You need to store the location of the root directory in a "global" variable that, again, goes into the 
         handle designed at step (1).

   (4)   Write __myfs_getattr_implem and debug it thoroughly, as best as you can with a filesystem that is reduced to one
         function. Writing this function will make you write helper functions to traverse paths, following the appropriate
         subdirectories inside the file system. Strive for modularity for these filesystem traversal functions.

   (5)   Design and implement __myfs_readdir_implem. You cannot test it besides by listing your root directory with ls -la and looking
         at the date of last access/modification of the directory (.). Be sure to understand the signature of that function and use
         caution not to provoke segfaults nor to leak memory.

   (6)   Design and implement __myfs_mknod_implem. You can now touch files with 

         touch foo

         and check that they start to exist (with the appropriate access/modification times) with ls -la.

   (7)   Design and implement __myfs_mkdir_implem. Test as above.

   (8)   Design and implement __myfs_truncate_implem. You can now create files filled with zeros:

         truncate -s 1024 foo

   (9)   Design and implement __myfs_statfs_implem. Test by running df before and after the truncation of a file to various lengths. 
         The free "disk" space must change accordingly.

   (10)  Design, implement and test __myfs_utimens_implem. You can now touch files at different dates (in the past, in the future).

   (11)  Design and implement __myfs_open_implem. The function can only be tested once __myfs_read_implem and __myfs_write_implem are
         implemented.

   (12)  Design, implement and test __myfs_read_implem and __myfs_write_implem. You can now write to files and read the data back:

         echo "Hello world" > foo
         echo "Hallo ihr da" >> foo
         cat foo

         Be sure to test the case when you unmount and remount the filesystem: the files must still be there, contain the same
         information and have the same access and/or modification times.

   (13)  Design, implement and test __myfs_unlink_implem. You can now remove files.

   (14)  Design, implement and test __myfs_unlink_implem. You can now remove directories.

   (15)  Design, implement and test __myfs_rename_implem. This function is extremely complicated to implement. Be sure to cover all 
         cases that are documented in man 2 rename. The case when the new path exists already is really hard to implement. Be sure to 
         never leave the filessystem in a bad state! Test thoroughly using mv on (filled and empty) directories and files onto 
         inexistant and already existing directories and files.

   (16)  Design, implement and test any function that your instructor might have left out from this list. There are 13 functions 
         __myfs_XXX_implem you have to write.

   (17)  Go over all functions again, testing them one-by-one, trying to exercise all special conditions (error conditions): set
         breakpoints in gdb and use a sequence of bash commands inside your mounted filesystem to trigger these special cases. Be
         sure to cover all funny cases that arise when the filesystem is full but files are supposed to get written to or truncated
         to longer length. There must not be any segfault; the user space program using your filesystem just has to report an
         error. Also be sure to unmount and remount your filesystem, in order to be sure that it contents do not change by
         unmounting and remounting. Try to mount two of your filesystems at different places and copy and move (rename!)
         (heavy) files (your favorite movie or song, an image of a cat etc.) from one mount-point to the other. None of the two FUSE
         processes must provoke errors. Find ways to test the case when files have holes as the process that wrote them seeked
         beyond the end of the file several times. Your filesystem must support these operations at least by making the holes explicit 
         zeros (use dd to test this aspect).

   (18)  Run some heavy testing: copy your favorite movie into your filesystem and try to watch it out of the filesystem.
*/

/* START __malloc_impl, realloc_impl, free_impl */

// BEGINNING OF STRUCTS

typedef struct s_AllocateFrom {
  size_t remaining;
  __off_t *next_space;
} AllocateFrom;

typedef struct s_List {
  __off_t *first_space;
} List;

// END OF STRUCTS

/* Memory allocation functions */
void *__malloc_impl(void *fsptr, size_t size);
void *__realloc_impl(void *fsptr, void *ptr, size_t size);
void __free_impl(void *fsptr, void *ptr);
/* End memory allocation functions */

// BEGINNING OF HELPER FUNCTIONS DECLARATION

/* Make an AllocateFrom item using length and start and add it to the list which does it in ascending order. */
static void add_allocation_space(List *LL, AllocateFrom *new_space);

/*
 */
static void *get_allocation(List *LL, size_t size);

// END OF HELPER FUNCTIONS DECLARATION

static void add_allocation_space(List *LL, AllocateFrom *new_space)
{
  //
}

static void *get_allocation(List *LL, size_t size)
{
  return NULL;
}

void *__malloc_impl(List *LL, size_t size)
{
  //

  return NULL;
}

/* If size is less than what already assign to *ptr just lock what is after size and add it using add_allocation_space. */
void *__realloc_impl(void *fsptr, void *ptr, size_t size)
{
  return NULL;
}

/* Add space back to List using add_allocation_space */
void __free_impl(void *fsptr, void *ptr)
{
  if (ptr == NULL) {
    return;
  }

  List *LL = get_free_memory_ptr(fsptr);

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
void *off_to_ptr(void *reference, __off_t offset)
{
  void *ptr = reference + offset;

  //Check that our pointer address didn't overflow
  if (ptr < reference) {
    return NULL;
  }

  return ptr;
}

__off_t ptr_to_off(void *reference, void *ptr)
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

List *get_free_memory_ptr(void *fsptr)
{
  return off_to_ptr(fsptr, ((handler_t *) fsptr)->free_memory);
}

void make_dir_node(void *fsptr, node_t *node, const char *name, size_t max_chld, __off_t parent_off_t)
{
  memset(node->name, '\0', NAME_MAX_LEN + ((size_t) 1));  //File all name characters to '\0'
  memcpy(node->name, name, strlen(name)); //Copy given name into node->name, memcpy(dst,src,n_bytes)
  update_time(node, 1);
  node->is_file = 0;
  directory_t *dict = &node->type.directory;
  dict->number_children = ((size_t) 1);  //We use the first child space for '..'

  //Call __malloc_impl() to get enough space for max_chld
  __off_t *ptr = ((__off_t *) __malloc_impl(fsptr, max_chld*sizeof(__off_t)));
  //TODO: Check that ptr was allocated with the amount wanted or more, but not less
  //Save the offset to get to the children
  dict->children = ptr_to_off(fsptr, ptr);
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
    node_t *root = off_to_ptr(fsptr, handle->root_dir);

    //Set the free blocks information
    //We had use a handler_t and a node_t for the root directory
    handle->free_memory = handle->root_dir + sizeof(node_t);  //This is just the offset
    free_block_t *fb = off_to_ptr(fsptr, handle->free_memory);

    //Set everything on memory to be 0 starting at the first free block + sizeof(size_t)
    fb->size = fssize - handle->free_memory;
    memset(((void *) fb) + sizeof(size_t), 0, fb->size - sizeof(size_t));
    fb->next_block = 0;

    //Set the root directory to be name '/' with 4 children where the parent is NULL
    make_dir_node(fsptr, root, "/", 4, 0);
  }
}

char *get_last_token(const char *path, unsigned long *token_len)
{
  unsigned long len = strlen(path);
  unsigned long idx;

  //Find last '/' in path
  for (idx = len-1; idx >= 0; idx--) {
    if (path[idx] == '/') break;
  }

  //idx is at '/' but we want to start a character after it
  idx++;

  //Set the length of the last node
  *token_len = len-idx;

  //Make a copy of the last token
  void *ptr = malloc((*token_len+1)*sizeof(char));

  //Check that malloc was successful
  if (ptr == NULL) {
    return NULL;
  }

  char *copy = (char *) ptr;
  strcpy(copy, &path[idx]); //strcpy(dst,src)

  //Add null character to terminate the string
  copy[*token_len] = '\0';

  return copy;
}

char **tokenize(const char token, const char *path, int skip_n_tokens)
{
  int n_tokens = 0;
  for (const char *c = path; *c != '\0'; c++) {
    if (*c == token) {
      n_tokens++;
    }
  }
  //n_tokens value would be of at least 1 because of root directory
  //Do not tokenize the last skip_n_tokens
  n_tokens -= skip_n_tokens;

  char **tokens = (char **) malloc(((u_int) (n_tokens+1))*sizeof(char *));
  const char *start = &path[1];  //Jump the first character which is '\'
  const char *end = start;
  char *t;

  //Populate tokens
  for (int i = 0; i < n_tokens; i++) {
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
  //Make array null terminated
  tokens[n_tokens] = NULL;

  return tokens;
}

void print_tokens(char **tokens)
{
  for ( ; *tokens; tokens++) {
    printf("%s\n", *tokens);
  }
}

node_t *get_node(void *fsptr, directory_t *dict, const char *child)
{
  size_t n_children = dict->number_children;
  __off_t *children = off_to_ptr(fsptr, dict->children);
  node_t *node;

  //Check if we need to go the parent directory
  if (strcmp(child, "..") == 0) {
    return ((node_t *) off_to_ptr(fsptr, children[0]));
  }

  //We start from the second children because the first one is ".." (parent)
  for (size_t i = ((size_t) 1); i < n_children; i++) {
    node = ((node_t *) off_to_ptr(fsptr, children[i]));
    if (strcmp(node->name, child)) {
      return node;
    }
  }

  return NULL;
}

node_t *path_solver(void *fsptr, const char *path, int skip_n_tokens)
{
  //Check if the path start at the root directory
  if (*path != '/') {
    return NULL;
  }

  //Get root directory
  node_t *node = off_to_ptr(fsptr, ((handler_t *) fsptr)->root_dir);
  //Break path into tokens
  char **tokens = tokenize('/', path, skip_n_tokens);

  for (char *token = *tokens; token != NULL; token++) {
    //Files cannot have children
    if (node->is_file) {
      return NULL;
    }
    //If token is "." we stay on the same directory
    if (strcmp(token, ".") != 0) {
      node = get_node(fsptr, &node->type.directory, token);
      //Check that the child was successfully retrieved
      if (node == NULL) {
        return NULL;
      }
    }
  }

  return node;
}

node_t *make_inode(void *fsptr, const char *path, int *errnoptr, int isfile)
{
  //Call path solver without the last node name because that is the file name if valid path name is given
  node_t *parent_node = path_solver(fsptr, path, 1);

  //Check that the file parent exist
  if (parent_node == NULL) {
    //TODO: set errnoptr
    return NULL;
  }

  //Check that the node returned is a directory
  if (parent_node->is_file) {
    //TODO: set errnoptr
    return NULL;
  }

  //Get directory from node
  directory_t *dict = &parent_node->type.directory;

  //Get last token which have the filename
  unsigned long len;
  char *new_node_name = get_last_token(path,&len);

  //Check that the parent don't contain a node with the same name as the one we are about to create
  if (get_node(fsptr,dict,new_node_name) != NULL) {
    //TODO: set errnoptr
    return NULL;
  }

  //Check that the name is between 1 and 255 characters long
  len = strlen(new_node_name);
  if ( (len == 0) || (len > 255) ) {
    //TODO: set errnoptr
    return NULL;
  }

  __off_t *children = &dict->children;
  free_block_t *block = (((void *) children) - sizeof(size_t));

  //Make the node and put it in the directory child list
  // First check if the directory list have free places to added nodes to
  //  Amount of memory allocated doesn't count the sizeof(size_t) as withing the available size
  size_t max_children = (block->size)/sizeof(__off_t);
  if (max_children == dict->number_children) {
    //Make more space for another children
    block = __realloc_impl(fsptr, block, block->size*2);
    //Check if malloc was successful
    if (((block->size)/sizeof(__off_t)) == dict->number_children) {
      //TODO: refuse to add the file
      return NULL;
    }
  }

  node_t *new_node = (node_t *) __malloc_impl(fsptr, sizeof(node_t));
  memset(new_node->name, '\0', NAME_MAX_LEN + ((size_t) 1));  //File all name characters to '\0'
  memcpy(new_node->name, new_node_name, len); //Copy given name into node->name, memcpy(dst,src,n_bytes)
  update_time(new_node, 1);

  //Add file node to directory children
  children[dict->number_children] = ptr_to_off(fsptr, new_node);
  dict->number_children++;
  update_time(parent_node, 1);

  if (isfile) {
    //Make a node for the file with size of 0
    new_node->is_file = 1;
    file_t *file = &new_node->type.file;
    file->total_size = 0;
    file->first_file_block = 0;
  }
  else {
    //Make a node for the file with size of 0
    new_node->is_file = 0;
    dict = &new_node->type.directory;
    dict->number_children = ((size_t) 1);  //We use the first child space for '..'

    //Call __malloc_impl() to get enough space for 4 children
    __off_t *ptr = ((__off_t *) __malloc_impl(fsptr, 4*sizeof(__off_t)));
    //TODO: Check that ptr was allocated with the amount wanted or more, but not less
    //Save the offset to get to the children
    dict->children = ptr_to_off(fsptr, ptr);
    //Set first children to point to its parent
    *ptr = ptr_to_off(fsptr, parent_node);
  }

  return new_node;
}

void free_file_info(void *fsptr, file_t *file)
{
  file_block_t *block = off_to_ptr(fsptr, file->first_file_block);
  file_block_t *next;

  //Iterate over all blocks until a block is pointing to fsptr meaning that we are done
  while (((void *) block) != fsptr) {
    //Free block data information
    __free_impl(fsptr, off_to_ptr(fsptr, block->data));
    //Save next block pointer
    next = off_to_ptr(fsptr, block->next_file_block);
    //Free current block
    __free_impl(fsptr, block);
    //Update current block with the next file_t for the next iteration
    block = next;
  }
}

void remove_node(void *fsptr, directory_t *dict, node_t *node)
{
  //TODO: Iterate over the files in dict and remove the file_node which we assume to be already free by calling free_file_info with &file_node->type.file
  size_t n_children = dict->number_children;
  __off_t *children = off_to_ptr(fsptr, dict->children);
  size_t idx;
  __off_t node_off = ptr_to_off(fsptr, node);

  //Find the idx where the node is at
  for (idx = 1; idx < n_children; idx++) {
    if (children[idx] == node_off) {
      break;
    }
  }

  //File must be at idx
  __free_impl(fsptr, node);

  //Move the remaining nodes one to the left to cover the node remove
  for ( ; idx < n_children-1; idx++) {
    children[idx] = children[idx+1];
  }

  //Set the last to have offset of zero and update number of children
  children[idx] = ((__off_t) 0);
  dict->number_children--;

  //See if we can free some memory by half while keeping at least 4 offsets
  //TODO:
}
/* End of helper functions */

/* Implements an emulation of the stat system call on the filesystem of size fssize pointed to by fsptr. 

   If path can be followed and describes a file or directory that exists and is accessable, the access information is 
   put into stbuf. 

   On success, 0 is returned. On failure, -1 is returned and the appropriate error code is put into *errnoptr.

   man 2 stat documents all possible error codes and gives more detail on what fields of stbuf need to be filled in. Essentially,
   only the following fields need to be supported:

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

/* Implements an emulation of the readdir system call on the filesystem of size fssize pointed to by fsptr. 

   If path can be followed and describes a directory that exists and is accessable, the names of the subdirectories and files 
   contained in that directory are output into *namesptr. The . and .. directories must not be included in that listing.

   If it needs to output file and subdirectory names, the function starts by allocating (with calloc) an array of pointers to
   characters of the right size (n entries for n names). Sets *namesptr to that pointer. It then goes over all entries
   in that array and allocates, for each of them an array of characters of the right size (to hold the i-th name, together 
   with the appropriate '\0' terminator). It puts the pointer into that i-th array entry and fills the allocated array
   of characters with the appropriate name. The calling function will call free on each of the entries of *namesptr and 
   on *namesptr.

   The function returns the number of names that have been put into namesptr. 

   If no name needs to be reported because the directory does not contain any file or subdirectory besides . and .., 0 is 
   returned and no allocation takes place.

   On failure, -1 is returned and the *errnoptr is set to the appropriate error code. 

   The error codes are documented in man 2 readdir.

   In the case memory allocation with malloc/calloc fails, failure is indicated by returning -1 and setting *errnoptr to EINVAL.
*/
int __myfs_readdir_implem(void *fsptr, size_t fssize, int *errnoptr, const char *path, char ***namesptr)
{
  node_t *node = path_solver(fsptr, path, 0);

  //Path could not be solved, TODO: specify errnoptr
  if (node == NULL) {
    return -1;
  }

  //Check that the node is a directory, TODO: specify errnoptr
  if (node->is_file) {
    return -1;
  }

  //Check that directory have more than ".", ".." nodes inside
  directory_t *dict = &node->type.directory;
  if (dict->number_children == 1) {
    return 0;
  }

  //Allocate space for all children, except "." and ".."
  size_t n_children = dict->number_children-((size_t) 1);
  void **ptr = calloc(n_children, sizeof(char *));
  __off_t *children = off_to_ptr(fsptr, dict->children);

  //Check that calloc call was successful
  if (ptr == NULL) {
    *errnoptr = EINVAL;
    return -1;
  }

  char **names = ((char **) ptr);

  //Fill array of names
  for (size_t i = ((size_t) 1); i < n_children; i++) {
    node = ((node_t *) off_to_ptr(fsptr, children[i]));
    strcpy(names[i-1], node->name); //strcpy(dst,src)
  }

  *namesptr = names;
  return ((int) n_children);
}

/* Implements an emulation of the mknod system call for regular files on the filesystem of size fssize pointed to by fsptr.

   This function is called only for the creation of regular files.

   If a file gets created, it is of size zero and has default ownership and mode bits.

   The call creates the file indicated by path.

   On success, 0 is returned.

   On failure, -1 is returned and *errnoptr is set appropriately.

   The error codes are documented in man 2 mknod.
*/
int __myfs_mknod_implem(void *fsptr, size_t fssize, int *errnoptr, const char *path)
{
  //Make a directory, 1 because it is a file
  node_t *node = make_inode(fsptr, path, errnoptr, 1);

  //Check if the node was successfully created, if it wasn't the errnoptr was already set so we just return failure with -1
  if (node == NULL) {
    return -1;
  }

  return 0;
}

/* Implements an emulation of the unlink system call for regular files on the filesystem of size fssize pointed to by fsptr.

   This function is called only for the deletion of regular files.

   On success, 0 is returned.

   On failure, -1 is returned and *errnoptr is set appropriately.

   The error codes are documented in man 2 unlink.
*/
int __myfs_unlink_implem(void *fsptr, size_t fssize, int *errnoptr, const char *path)
{
  //Call path_solver with a 1 because we want the directory node where the filename belongs to
  node_t *node = path_solver(fsptr, path, 1);

  //Check that the file parent exist
  if(node == NULL){
    *errnoptr = ENOENT;
    return -1;
  }

  //Check that the node returned is a directory
  if (node->is_file) {
    //TODO: set errnoptr
    return -1;
  }

  //Get directory from node
  directory_t *dict = &node->type.directory;

  //Get last token which have the filename
  unsigned long len;
  char *filename = get_last_token(path, &len);

  //Check that the parent don't contain a node with the same name as the one we are about to create
  node_t *file_node = get_node(fsptr, dict, filename);

  //Check that file_node is actually a file
  if (file_node->is_file == 0) {
    //Path given lead to a directory not a file
    //TODO: set errnoptr
    return -1;
  }

  //Free file information
  file_t *file = &file_node->type.file;
  if (file->total_size != 0) {
    free_file_info(fsptr, file);
  }

  //Remove file_node from parent directory
  remove_node(fsptr, dict, file_node);

  //Free file_node
  __free_impl(fsptr, file_node);

  return 0;
}

/* Implements an emulation of the rmdir system call on the filesystem of size fssize pointed to by fsptr. 

   The call deletes the directory indicated by path.

   On success, 0 is returned.

   On failure, -1 is returned and *errnoptr is set appropriately.

   The function call must fail when the directory indicated by path is not empty (if there are files or subdirectories
   other than . and ..).

   The error codes are documented in man 2 rmdir.
*/
int __myfs_rmdir_implem(void *fsptr, size_t fssize, int *errnoptr, const char *path)
{
  //We can access the parent directory as the first children of the return directory
  //TODO: Fix the algorithm
  node_t *node = path_solver(fsptr, path, 0);

  //Check that the node exist
  if (node == NULL){
    *errnoptr = ENOENT;
    return -1;
  }

  //Check that the node returned is not a file
  if (node->is_file) {
    //TODO: set errnoptr
    return -1;
  }

  //Check that the directory is empty (only the parent can be there "..")
  directory_t *dict = &node->type.directory;
  if (dict->number_children != 1) {
    *errnoptr = ENOTEMPTY;
    return -1;
  }

  //Get parent directory
  __off_t *children = off_to_ptr(fsptr, dict->children);
  node_t *parent_node = off_to_ptr(fsptr, *children);

  //Free children of node and the node itself
  __free_impl(fsptr, children);
  __free_impl(fsptr, node);

  //Remove directory from parent directory
  remove_node(fsptr, &parent_node->type.directory, node);

  return 0;
}

/* Implements an emulation of the mkdir system call on the filesystem of size fssize pointed to by fsptr. 

   The call creates the directory indicated by path.

   On success, 0 is returned.

   On failure, -1 is returned and *errnoptr is set appropriately.

   The error codes are documented in man 2 mkdir.
*/
int __myfs_mkdir_implem(void *fsptr, size_t fssize, int *errnoptr, const char *path)
{
  //Make a directory, 0 because it is not a file
  node_t *node = make_inode(fsptr, path, errnoptr, 0);

  //Check if the node was successfully created, if it wasn't the errnoptr was already set so we just return failure with -1
  if (node == NULL) {
    return -1;
  }

  return 0;
}

/* Implements an emulation of the rename system call on the filesystem of size fssize pointed to by fsptr. 

   The call moves the file or directory indicated by from to to.

   On success, 0 is returned.

   On failure, -1 is returned and *errnoptr is set appropriately.

   Caution: the function does more than what is hinted to by its name. In cases the from and to paths differ, the file is moved out of 
   the from path and added to the to path.

   The error codes are documented in man 2 rename.
*/
int __myfs_rename_implem(void *fsptr, size_t fssize, int *errnoptr, const char *from, const char *to)
{
  /* STUB */
  return -1;
}

/* Implements an emulation of the truncate system call on the filesystem of size fssize pointed to by fsptr. 

   The call changes the size of the file indicated by path to offset bytes.

   When the file becomes smaller due to the call, the extending bytes are removed. When it becomes larger, zeros are appended.

   On success, 0 is returned.

   On failure, -1 is returned and *errnoptr is set appropriately.

   The error codes are documented in man 2 truncate.
*/
int __myfs_truncate_implem(void *fsptr, size_t fssize, int *errnoptr, const char *path, off_t offset)
{
  /* STUB */
  return -1;
}

/* Implements an emulation of the open system call on the filesystem  of size fssize pointed to by fsptr, without actually performing
   the opening of the file (no file descriptor is returned).

   The call just checks if the file (or directory) indicated by path can be accessed, i.e. if the path can be followed to an existing
   object for which the access rights are granted.

   On success, 0 is returned.

   On failure, -1 is returned and *errnoptr is set appropriately.

   The two only interesting error codes are 

   * EFAULT: the filesystem is in a bad state, we can't do anything

   * ENOENT: the file that we are supposed to open doesn't exist (or a subpath).

   It is possible to restrict ourselves to only these two error conditions. It is also possible to implement more detailed error
   condition answers.

   The error codes are documented in man 2 open.
*/
int __myfs_open_implem(void *fsptr, size_t fssize, int *errnoptr, const char *path)
{
  //Get the node where the file is located
  node_t *node = path_solver(fsptr, path, 0);

  // Checks if path is valid, if not valid return -1
  if (node == NULL) {
    //TODO: Set errnoptr
    return -1;
  }

  //Checks if node is a file, if it is a file return 0
  return node->is_file ? 0 : -1;
}

/* Implements an emulation of the read system call on the filesystem of size fssize pointed to by fsptr.

   The call copies up to size bytes from the file indicated by path into the buffer, starting to read at offset. See the man page
   for read for the details when offset is beyond the end of the file etc.

   On success, the appropriate number of bytes read into the buffer is returned. The value zero is returned on an end-of-file condition.

   On failure, -1 is returned and *errnoptr is set appropriately.

   The error codes are documented in man 2 read.
*/
int __myfs_read_implem(void *fsptr, size_t fssize, int *errnoptr, const char *path, char *buf, size_t size, off_t offset)
{
  /* STUB */
  return -1;
}

/* Implements an emulation of the write system call on the filesystem of size fssize pointed to by fsptr.

   The call copies up to size bytes to the file indicated by path into the buffer, starting to write at offset. See the man page
   for write for the details when offset is beyond the end of the file etc.

   On success, the appropriate number of bytes written into the file is returned. The value zero is returned on an end-of-file condition.

   On failure, -1 is returned and *errnoptr is set appropriately.

   The error codes are documented in man 2 write.
*/
int __myfs_write_implem(void *fsptr, size_t fssize, int *errnoptr, const char *path, const char *buf, size_t size, off_t offset)
{
  /* STUB */
  return -1;
}

/* Implements an emulation of the utimensat system call on the filesystem of size fssize pointed to by fsptr.

   The call changes the access and modification times of the file or directory indicated by path to the values in ts.

   On success, 0 is returned.

   On failure, -1 is returned and *errnoptr is set appropriately.

   The error codes are documented in man 2 utimensat.
*/
int __myfs_utimens_implem(void *fsptr, size_t fssize, int *errnoptr, const char *path, const struct timespec ts[2])
{
  /* STUB */
  return -1;
}

/* Implements an emulation of the statfs system call on the filesystem of size fssize pointed to by fsptr.

   The call gets information of the filesystem usage and puts in into stbuf.

   On success, 0 is returned.

   On failure, -1 is returned and *errnoptr is set appropriately.

   The error codes are documented in man 2 statfs.

   Essentially, only the following fields of struct statvfs need to be supported:

   f_bsize   fill with what you call a block (typically 1024 bytes)
   f_blocks  fill with the total number of blocks in the filesystem
   f_bfree   fill with the free number of blocks in the filesystem
   f_bavail  fill with same value as f_bfree
   f_namemax fill with your maximum file/directory name, if your filesystem has such a maximum
*/
int __myfs_statfs_implem(void *fsptr, size_t fssize, int *errnoptr, struct statvfs* stbuf)
{
  /* STUB */
  return -1;
}

/* END of FUSE implementation */

