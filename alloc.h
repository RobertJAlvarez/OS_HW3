#ifndef _LINKED_LIST_
#define _LINKED_LIST_

// BEGINNING OF STRUCTS
typedef struct s_AllocateFrom {
  size_t remaining;
  struct s_AllocateFrom *next_space;
} AllocateFrom;

typedef struct s_List {
  struct s_AllocateFrom *first_space;
} List;
// END OF STRUCTS

/* If size is zero, return NULL. Otherwise, call get_allocation_space with size. */
void *__malloc_impl(List *LL, size_t size);

/* If size is less than what already assign to *ptr just lock what is after size and add it using add_allocation_space. */
void *__realloc_impl(List *LL, void *ptr, size_t size);

/* Add space back to List using add_allocation_space */
void __free_impl(List *LL, void *ptr);

#endif
