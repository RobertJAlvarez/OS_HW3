#include <stddef.h>
#include "alloc.h"
#include <stdio.h>  //printf()

/* If size is zero, return NULL. Otherwise, call get_allocation_space with size. */
void *__malloc_impl(size_t size)
{
  return NULL;
}

/* If size is less than what already assign to *ptr just lock what is after size and add it using add_allocation_space. */
void *__realloc_impl(void *ptr, size_t size)
{
  return NULL;
}

/* Call malloc and iterate over the point to change everything to '0's. */
void *__calloc_impl(size_t count, size_t size)
{
  return NULL;
}

/* Add space back to List using add_allocation_space */
void __free_impl(void *ptr)
{
  return;
}

