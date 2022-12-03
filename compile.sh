#Demount fuse
fusermount -u ~/fuse-mnt
fusermount -u ~/fuse-mnt

#Delete unnecessary files
make clean

#Compile code
gcc -g -O0 -Wall myfs.c implementation.c `pkg-config fuse --cflags --libs` -o myfs

#Run gdb
gdb --args ./myfs --backupfile=test.myfs ~/fuse-mnt/ -f
