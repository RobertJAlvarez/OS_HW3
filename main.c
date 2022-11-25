#include <unistd.h>
#include <stdio.h>  //printf()
#include <stdlib.h>
#include <string.h>
#include "implementation.h"

int main(void)
{
  //printf("[%d %d %d %d:%d:%d]\n", t.day, t.month+1, t.year+1900, t.hour, t.minute, t.second<<1);

  const char path[85] = "/Users/robertalvarez/OneDrive - University of Texas at El Paso/Fall_2022/CS_4375/HW3";
  printf("Full path: %s\n", path);

  //Tokenize all of them but eh last one and print them
  char **tokens = tokenize('/', path, 1);
  print_tokens(tokens);

  //Tokenize the last token and print it with its size
  unsigned long len;
  char *last_token = get_last_token(path, &len);

  printf("Last token: %s\n", last_token);
  printf("len: %lu =? strlen(last_token): %lu\n", len, strlen(last_token));

  return 0;
}
