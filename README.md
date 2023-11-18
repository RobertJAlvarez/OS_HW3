# File-system using FUSE

Design and implement a file-system that runs in memory but that can be
initialized from and written back to a backup-file. This file-system is
based on FUSE, through `myfs.c`.

FUSE implementation logic is in `implementation.c`. The 13 functions that
implement FUSE are:
```c
1.  int __myfs_getattr_implem(
      void *fsptr,
      size_t fssize,
      int *errnoptr,
      uid_t uid,
      gid_t gid,
      const char *path,
      struct stat *stbuf
    );
2.  int __myfs_readdir_implem(
      void *fsptr,
      size_t fssize,
      int *errnoptr,
      const char *path,
      char ***namesptr
    );
3.  int __myfs_mknod_implem(
      void *fsptr,
      size_t fssize,
      int *errnoptr,
      const char *path
    );
4.  int __myfs_unlink_implem(
      void *fsptr,
      size_t fssize,
      int *errnoptr,
      const char *path
    );
5.  int __myfs_rmdir_implem(
      void *fsptr,
      size_t fssize,
      int *errnoptr,
      const char *path
    );
6.  int __myfs_mkdir_implem(
      void *fsptr,
      size_t fssize,
      int *errnoptr,
      const char *path
    );
7.  int __myfs_rename_implem(
      void *fsptr,
      size_t fssize,
      int *errnoptr,
      const char *from,
      const char *to
    );
8.  int __myfs_truncate_implem(
      void *fsptr,
      size_t fssize,
      int *errnoptr,
      const char *path,
      off_t offset
    );
9.  int __myfs_open_implem(
      void *fsptr,
      size_t fssize,
      int *errnoptr,
      const char *path
    );
10. int __myfs_read_implem(
      void *fsptr,
      size_t fssize,
      int *errnoptr,
      const char *path,
      char *buf,
      size_t size,
      off_t offset
    );
11. int __myfs_write_implem(
      void *fsptr,
      size_t fssize,
      int *errnoptr,
      const char *path,
      const char *buf,
      size_t size,
      off_t offset
    );
12. int __myfs_utimens_implem(
      void *fsptr,
      size_t fssize,
      int *errnoptr,
      const char *path,
      const struct timespec ts[2]
    );
13. int __myfs_statfs_implem(
      void *fsptr,
      size_t fssize,
      int *errnoptr,
      struct statvfs* stbuf
    );
```
