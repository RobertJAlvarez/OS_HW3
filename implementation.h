#ifndef _MYFS_FUNCT_
#define _MYFS_FUNCT_

/* Helper functions */
void print_sizeof_struct(void);
char **tokenize(const char token, const char *path);
void print_tokens(char **tokens);
/* End of helper functions */

/* Project functions */
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
/* End of project functions */

#endif