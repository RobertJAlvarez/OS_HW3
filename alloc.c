#include <stddef.h>
#include <sys/mman.h> //mmap(void *addr, size_t len, int prot, int flags, int fd, off_t offset)  munmap(void *addr, size_t len)
#include <unistd.h>   //ssize_t getpagesize(void)
#include <string.h>
#include "alloc.h"

// BEGINNING OF HELPER FUNCTIONS DECLARATION

/* Make an AllocateFrom item using length and start and add it to the list which does it in ascending order. */
void add_allocation_space(List *LL, AllocateFrom *new_space);

/*
 */
void *get_allocation(List *LL, size_t size);

// END OF HELPER FUNCTIONS DECLARATION

/* Make an AllocateFrom item using length and start and add it to the list which does it in ascending order */
void add_allocation_space(List *LL, AllocateFrom *alloc)
{
  AllocateFrom *temp = LL->first_space;

  //new_space address is less than the first_space in LL
  if (temp > alloc) {
    /* At this point we know that alloc comes before LL->first_space */
    LL->first_space = alloc; //Update first space
    //Check if we can merge LL->first_space and alloc
    if ( (((char *) alloc) + sizeof(size_t) + alloc->remaining) == ((char *) temp) ) {
      //Combine the spaces available
      alloc->remaining += sizeof(size_t) + temp->remaining;
      //Update pointers
      alloc->next_space = temp->next_space;
    }
    //We couldn't merge so we just add it as the first_space and update pointers
    else {
      alloc->next_space = temp;
    }
  }
  //Find after what pointer does alloc should be added
  else {
    //Get the last pointer that is in lower memory than alloc
    while ( (temp->next_space != NULL) && (temp->next_space < alloc) ) {
      temp = temp->next_space;
    }
    /* Merge alloc and the space after alloc */
    //At this point, temp is before alloc and alloc is before temp->next_space. But, there is no guaranty that temp->next_space != NULL
    AllocateFrom *after_alloc = temp->next_space;
    if (after_alloc != NULL) {
      //Check if we can merge alloc and after_alloc
      if ( (((char *) alloc) + sizeof(size_t) + alloc->remaining) == ((char *) after_alloc) ) {
        alloc->remaining += sizeof(size_t) + after_alloc->remaining;
        alloc->next_space = after_alloc->next_space;
      }
      //We couldn't merge them
      else {
        alloc->next_space = after_alloc;
      }
    }
    //alloc is the last space available in memory ascending order
    else {
      alloc->next_space = NULL;
    }
    /* Merge temp (which is before alloc) and alloc */
    if ( (((char *) temp) + sizeof(size_t) + temp->remaining) == ((char *) alloc) ) {
      temp->remaining += sizeof(size_t) + alloc->remaining;
      temp->next_space = alloc->next_space;
    }
    //We couldn't merge them
    else {
      temp->next_space = alloc;
    }
  }
}

void *get_allocation(List *LL, size_t size)
{
  AllocateFrom *alloc = LL->first_space;
  AllocateFrom *ptr = NULL;

  //If the first page have just enough space from the first_space in our LL
  if ( (alloc->remaining >= size) && (alloc->remaining < (size+sizeof(AllocateFrom))) ) {
    //Everything on the first space is taken so now LL point to the second space to use the first one
    LL->first_space = alloc->next_space;
    //Get ptr to point to the beginning of the first space to return it
    ptr = alloc;
  }
  //If the first block have more space that what is asked for and it can create another AllocateFrom object without issues
  else if (alloc->remaining > size) {
    //LL is now pointing to what is remaining after using size
    LL->first_space = (AllocateFrom *) (((void *) alloc) + sizeof(size_t) + size);
    //Same pointer to second page but now on the new first_space
    LL->first_space->next_space = alloc->next_space;
    //Update the remaining space in first_space after using size
    LL->first_space->remaining = alloc->remaining - size - sizeof(size_t);
    //Update new value of alloc, which is size
    alloc->remaining = size;
    //Get ptr to point to the beginning of the previous first space
    ptr = alloc;
  }
  //If the first page don't have enough space for what was asked
  else {
    //TODO: If no block can hold what is needed, we save the largest block found

    //Find a node that is pointing to an space where we can get size from
    while ( (alloc->next_space != NULL) && (alloc->next_space->remaining < size) ) {
      alloc = alloc->next_space;
    }

    //TODO: Check if we got everything or just a portion
    if (alloc->next_space == NULL) {
      //
    }
    //If we find a valid space to get memory from
    else {
      //Save the space in memory that is going to be returned
      ptr = alloc->next_space;
      //If ptr have just enough space to hold size
      if ( (ptr->remaining >= size) && (ptr->remaining < (size+sizeof(AllocateFrom))) ) {
        //Everything on ptr is taken so now alloc points to what is after ptr
        alloc->next_space = ptr->next_space;
      }
      //If ptr have enough space to hold size and create another AllocateFrom object
      else {
        //alloc is now pointing to what is remaining after using size from ptr
        alloc->next_space = (AllocateFrom *) (((void *) ptr) + sizeof(size_t) + size);
        //What is after alloc is now pointing to what ptr was pointing at
        alloc->next_space->next_space = ptr->next_space;
        //Update the remaining space in what is after alloc after using size
        alloc->next_space->remaining = ptr->remaining - size - sizeof(size_t);
        //Update ptr new remaining which is what it was asked for
        ptr->remaining = size;
      }
    }
  }

  //Adjust ptr to not overwrite remaining variable with the number of bytes passed
  return ((char *) ptr) + sizeof(size_t);
}

/* If size is zero, return NULL. Otherwise, call get_allocation_space with size. */
void *__malloc_impl(List *LL, size_t size)
{
  if (size == ((size_t) 0)) {
    return NULL;
  }

  return get_allocation(LL, size);
}

/* If size is less than what already assign to *ptr just lock what is after size and add it using add_allocation_space. */
void *__realloc_impl(List *LL, void *ptr, size_t size)
{
  //If size is 0, we free the ptr and return NULL
  if (size == ((size_t) 0)) {
    __free_impl(LL, ptr);
    return NULL;
  }

  //If ptr is NULL, realloc() is identical to a call to malloc() for size bytes.
  if (ptr == NULL) {
    return get_allocation(LL, size);
  }

  AllocateFrom *alloc = (AllocateFrom *) (((void *) ptr) - sizeof(size_t));
  AllocateFrom *temp;

  //If the new size is less than before but not enough to make an AllocateFrom object
  if ( (alloc->remaining >= size) && (alloc->remaining < (size + sizeof(AllocateFrom))) ) {
    return ptr;
  }
  //If the new size is less than before and we can create an AllocateFrom element to add to LL
  else if (alloc->remaining > size) {
    //Save what is left in temp and add it to the LL
    temp = (AllocateFrom *) (((void *) alloc) + sizeof(size_t) + size);
    temp->remaining = alloc->remaining - sizeof(size_t) - size;
    temp->next_space = NULL;
    add_allocation_space(LL, temp);
    //Update remaining space
    alloc->remaining = size;
  }
  //If we are asking for more than what we have in alloc
  else {
    //Get new space to copy to
    void *new_ptr = get_allocation(LL, size);
    //We couldn't get enough space
    if (new_ptr == NULL) {
      return NULL;
    }
    //Copy space where to copy to, so we can iterate without losing the beginning
    memcpy(new_ptr, ptr, alloc->remaining);
    //Put alloc back into the LL for reuse
    add_allocation_space(LL, alloc);
  }

  return ptr;
}

/* Add space back to List using add_allocation_space */
void __free_impl(List *LL, void *ptr)
{
  if (ptr == NULL) {
    return;
  }

  //Adjust ptr so size_t before to start on the size of pointer
  AllocateFrom *temp = (AllocateFrom *) (ptr - sizeof(size_t));
  add_allocation_space(LL, temp);
}

