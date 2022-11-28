#ifndef __MY_FUSE_IMPL__
#define __MY_FUSE_IMPL__

#include <time.h>

/* Definitions and type declarations */

#define MYFS_MAGIC ((uint32_t) 0xCAFEBABE)
#define NAME_MAX_LEN ((size_t) 255)
#define BLOCK_SIZE ((size_t) 1024)

typedef unsigned int u_int;
typedef size_t __off_t;

// END of definitions and type declarations

/* START memory allocation STRUCTS */

typedef struct s_AllocateFrom {
  size_t remaining;
  __off_t next_space;
} AllocateFrom;

typedef struct s_List {
  __off_t first_space;
} List;

// END OF STRUCTS

/* START of fuse STRUCTS */

typedef struct __handler_t {
  uint32_t magic;
  __off_t root_dir;
  __off_t free_memory;
  size_t size;
} handler_t;

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

typedef struct __inode_t {
  char name[NAME_MAX_LEN + ((size_t) 1)];
  char is_file;
  struct timespec times[2]; //times[0]: last access date, times[1]: last modification date
  union {
    file_t file;
    directory_t directory;
  } type;
} node_t;

// END OF STRUCTS

/* START memory allocation helper functions declarations */

void *__malloc_impl(void *fsptr, void *pref_ptr, size_t pref_to_beginning, size_t *size);
void *__realloc_impl(void *fsptr, void *orig_ptr, size_t *size);
void __free_impl(void *fsptr, void *ptr, size_t off_to_beginning);
void add_allocation_space(void *fspte, List *LL, AllocateFrom *alloc);
void *get_allocation(void *fsptr, List *LL, void *org_pref_ptr, size_t pref_to_beginning, size_t *size);

// END memory allocation functions

/* START fuse helper functions */

void *off_to_ptr(void *reference, __off_t offset);
__off_t ptr_to_off(void *reference, void *ptr);
void update_time(node_t *node, int new_node);
List *get_free_memory_ptr(void *fsptr);
void handler(void *fsptr, size_t fssize);
char *get_last_token(const char *path, unsigned long *token_len);
char **tokenize(const char token, const char *path, int skip_n_tokens);
//TODO: Delete next function before turning in the project
void print_tokens(char **tokens);
node_t *get_node(void *fsptr, directory_t *dict, const char *child);
node_t *path_solver(void *fsptr, const char *path, int skip_n_tokens);
node_t *make_inode(void *fsptr, const char *path, int *errnoptr, int isfile);
void free_file_info(void *fsptr, file_t *file);
void remove_node(void *fsptr, directory_t *dict, node_t *node);

// END of fuse helper functions

/* START fuse functions declarations */

int __myfs_getattr_implem(void *fsptr, size_t fssize, int *errnoptr, uid_t uid, gid_t gid, const char *path, struct stat *stbuf);
int __myfs_readdir_implem(void *fsptr, size_t fssize, int *errnoptr, const char *path, char ***namesptr);
int __myfs_mknod_implem(void *fsptr, size_t fssize, int *errnoptr, const char *path);
int __myfs_unlink_implem(void *fsptr, size_t fssize, int *errnoptr, const char *path);
int __myfs_rmdir_implem(void *fsptr, size_t fssize, int *errnoptr, const char *path);
int __myfs_mkdir_implem(void *fsptr, size_t fssize, int *errnoptr, const char *path);
int __myfs_rename_implem(void *fsptr, size_t fssize, int *errnoptr, const char *from, const char *to);
int __myfs_truncate_implem(void *fsptr, size_t fssize, int *errnoptr, const char *path, off_t offset);
int __myfs_open_implem(void *fsptr, size_t fssize, int *errnoptr, const char *path);
int __myfs_read_implem(void *fsptr, size_t fssize, int *errnoptr, const char *path, char *buf, size_t size, off_t offset);
int __myfs_write_implem(void *fsptr, size_t fssize, int *errnoptr, const char *path, const char *buf, size_t size, off_t offset);
int __myfs_utimens_implem(void *fsptr, size_t fssize, int *errnoptr, const char *path, const struct timespec ts[2]);
int __myfs_statfs_implem(void *fsptr, size_t fssize, int *errnoptr, struct statvfs* stbuf);

//END of fuse function declarations

#endif
