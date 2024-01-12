#include <stdio.h>  //printf()
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include "implementation.h"

void print_tokens(char **tokens) {
  for (; *tokens; tokens++) {
    printf("%s\n", *tokens);
  }
}

int main(void) {
  const char path[85] =
      "/Users/robertalvarez/OneDrive - University of Texas at El "
      "Paso/Fall_2022/CS_4375/HW3";
  printf("Full path: %s\n", path);

  // Tokenize all of them but eh last one and print them
  char **tokens = tokenize('/', path, 1);
  print_tokens(tokens);

  // Tokenize the last token and print it with its size
  unsigned long len;
  char *last_token = get_last_token(path, &len);

  printf("Last token: %s\n", last_token);
  printf("len: %lu =? strlen(last_token): %lu\n", len, strlen(last_token));

  const char path2[6] = "/file";
  printf("Full path: %s\n", path2);
  tokens = tokenize('/', path2, 0);
  for (char **token = tokens; *token; token++) {
    printf("token = %s\n", *token);
  }

  printf("sizeof(handler_t) = %zx\n", sizeof(handler_t));
  printf("sizeof(node_t) = %zx\n", sizeof(node_t));
  printf("sizeof(directory_t) = %zx\n", sizeof(directory_t));
  printf("sizeof(file_t) = %zx\n", sizeof(file_t));
  printf("sizeof(file_block_t) = %zx\n", sizeof(file_block_t));
  printf("sizeof(size_t) = %zx\n", sizeof(size_t));
  printf("sizeof(struct timespec) = %zx\n\n", sizeof(struct timespec));

  size_t fssize = 2048;
  void *fsptr = mmap(NULL, fssize, PROT_WRITE | PROT_READ,
                     MAP_SHARED | MAP_ANONYMOUS, -1, 0);

  printf("fssize = %zx\n", fssize);
  if (fsptr != NULL) {
    handler(fsptr, fssize);
    size_t *size = malloc(sizeof(size_t));
    *size = 0x10;
    void *alloc = __malloc_impl(fsptr, NULL, size);

    printf("fsptr = %p\n", fsptr);
    printf("alloc = %p\n", alloc);
    printf("alloc-fsptr = %zx\n", (alloc - fsptr));

    List *LL = (List *)get_free_memory_ptr(fsptr);
    AllocateFrom *fb = off_to_ptr(fsptr, LL->first_space);
    printf("fb->remaining = %zx\n", fb->remaining);
    printf("fb->next_space = %zx\n", fb->next_space);

    *size = 0x10;
    void *alloc2 = __malloc_impl(fsptr, alloc, size);

    printf("fsptr = %p\n", fsptr);
    printf("alloc2 = %p\n", alloc2);
    printf("alloc2-fsptr = %zx\n", (alloc2 - fsptr));
    __free_impl(fsptr, alloc);

    free(size);
    munmap(fsptr, fssize);
  }

  return 0;
}
