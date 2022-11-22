#ifndef _LINKED_LIST_
#define _LINKED_LIST_

/* If size is zero, return NULL. Otherwise, call get_allocation_space with size. */
void *__malloc_impl(size_t size);

/* If size is less than what already assign to *ptr just lock what is after size and add it using add_allocation_space. */
void *__realloc_impl(void *ptr, size_t size);

/* Call malloc and iterate over the point to change everything to '0's. */
void *__calloc_impl(size_t count, size_t size);

/* Add space back to List using add_allocation_space */
void __free_impl(void *ptr);

#endif
