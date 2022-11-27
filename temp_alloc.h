#ifndef _ALLOC_FUNCT_
#define _ALLOC_FUNCT_

// BEGINNING OF STRUCTS

typedef struct s_AllocateFrom {
  size_t remaining;
  __off_t next_space;
} AllocateFrom;

typedef struct s_List {
  __off_t first_space;
} List;

// END OF STRUCTS

/* Search for the block after after_this. If it is found on the free list we get the amount of bytes needed or as many as you can
 * from it. Otherwise, make new_one to be pointing to the starting point of the largest block found on the list. The value inside
 * remaining contains the amount of bytes wanted and by the end of the function it have the original value - bytes collected.
 */
void follow_up_block(void *after_this, void *new_one, size_t *remaining);

/* If less space is required, see if we can make an empty block. Otherwise, we do nothing. If more space is required, search for
 * the first block that have enough space, copy the information to it and free the previous block.
 */
void *__realloc_impl(void *oldPtr, size_t how_much);

#endif
