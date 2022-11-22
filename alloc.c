#include <stddef.h>
#include <sys/mman.h> //mmap(void *addr, size_t len, int prot, int flags, int fd, off_t offset)  munmap(void *addr, size_t len)
#include <unistd.h>   //ssize_t getpagesize(void)
#include "alloc.h"

// BEGINNING OF HELPER FUNCTIONS DECLARATION

/* Initialize the linked list to keep the history. */
int init_LL(void);

/* Use mmap to get a page of memory, use the beginning for the AllocateFrom object. */
AllocateFrom *make_allocation_space(void);

/* Make an AllocateFrom item using length and start and add it to the list which does it in ascending order. */
void add_allocation_space(AllocateFrom *new_space);

/* Iterate LL to get a pointer that can hold size or make a new PAGE or an individual mmap for something greater than PAGE-sizeof(size_t),
 * such pointer must have size in location ptr - sizeof(size_t). */
void *get_allocation(size_t size);

/* Check if n1 * n2 can be hold in a size_t type. If so, return 1 and store the value in c. Otherwise, return 0 */
static int __try_size_t_multiply(size_t *c, size_t n1, size_t n2);

// END OF HELPER FUNCTIONS DECLARATION

// BEGINNING OF GLOBAL VARIABLES DECLARATION

size_t PAGE;  //define the size of a page
List *LL;     //Start a list to save all the allocation spaces to use in malloc, realloc, and calloc

// END OF GLOBAL VARIABLES DECLARATION

/* Initialize the linked list to keep the history */
int init_LL()
{
  void *ptr = mmap(NULL, sizeof(List), PROT_WRITE|PROT_READ, MAP_SHARED|MAP_ANONYMOUS, -1,0);
  //Make sure that mmap was successful
  if (ptr == MAP_FAILED) {
    return -1;
  }
  LL = (List *) ptr;

  //define the size of a page
  if (PAGE == 0) {
    PAGE = (size_t) getpagesize();
  }

  LL->first_space = NULL;
  return 0;
}

/* Use mmap to get a page of memory, use the beginning for the Map object and the rest for the AllocateFrom object */
AllocateFrom *make_allocation_space()
{
  //Allocate a page of memory for a Map and the rest to AllocateFrom
  AllocateFrom *ptr = (AllocateFrom *) mmap(NULL, PAGE, PROT_WRITE|PROT_READ, MAP_SHARED|MAP_ANONYMOUS, -1,0);

  //Make sure that mmap was successful
  if (ptr == MAP_FAILED) {
    return NULL;
  }

  ptr->remaining = PAGE - sizeof(size_t);
  ptr->next_space = NULL;

  return ptr;
}

/* Make an AllocateFrom item using length and start and add it to the list which does it in ascending order */
void add_allocation_space(AllocateFrom *alloc)
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
      //Check if by adding new_space we get everything back so we can free the page
      if ( alloc->remaining == (PAGE - sizeof(size_t)) ) {
        //Save new first_space
        LL->first_space = alloc->next_space;
        //Free previous first_space
        if (munmap(alloc, PAGE) != 0) { //If unmaping was unsuccessful
          return;
        }
        //If we have free every page mapped, we free the LL as well.
        if (LL->first_space == NULL) {
          if (munmap(LL, sizeof(List)) == 0) { //If unmaping was successful
            LL = NULL;
          }
        }
      }
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
        //Check if the merge free an entire page so we can unmap it from memory
        if ( alloc->remaining == (PAGE - sizeof(size_t)) ) {
          //Update pointers so now prev points to what alloc was pointing
          temp->next_space = alloc->next_space;
          //unmap alloc
          munmap(alloc, PAGE);
          //alloc has been added to the linked list and it was the beginning of the page so it was free but we still
          //have temp which comes before that (coming from another page) so we don't check for empty LL to free it
          return;
        }
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
      //Check if the merge free an entire page so we can unmap it from memory
      if (temp->remaining == (PAGE - sizeof(size_t)) ) {
        /* See which AllocateFrom was pointing to temp so we can update pointers and unmap temp */
        //Check if temp is the first element on the list
        if (LL->first_space == temp) {
          //Update LL first_space pointer
          LL->first_space = temp->next_space;
          //Unmap temp
          if (munmap(temp, PAGE) != 0) {  //If unmaping was unsuccessful
            return;
          }
          //Check if temp was the last thing on the list
          if (LL->first_space == NULL) {
            //Unmap the linked list
            if (munmap(LL, sizeof(List)) == 0) { //If munmaping was successful
              LL = NULL;
            }
          }
        }
        /* temp needs to be unmap but it is not the first thing on the list so we don't have what is pointing to it */
        else {
          //Get what is pointing to temp
          AllocateFrom *before_temp = LL->first_space;
          while (before_temp->next_space != temp) {
            before_temp = before_temp->next_space;
          }
          //Update pointers
          before_temp->next_space = temp->next_space;
          //Unmap temp
          munmap(temp, PAGE);
        }
      }
    }
    //We couldn't merge them
    else {
      temp->next_space = alloc;
    }
  }
}

/* Iterate LL to get a pointer that can hold size or make a new PAGE or an individual mmap for something greater than PAGE-sizeof(size_t),
 * such pointer must have size in location ptr - sizeof(size_t)
 */
void *get_allocation(size_t size)
{
  AllocateFrom *alloc = LL->first_space;
  AllocateFrom *ptr = NULL;

  //If there is no where to get space from, we make some space
  if (alloc == NULL) {
    LL->first_space = make_allocation_space();
    if (LL->first_space == NULL) {
      return NULL;
    }
    alloc = LL->first_space;
  }

  //If the first page have just enough space from the first_space in our LL
  if ( (alloc->remaining >= size) && (alloc->remaining < (size+sizeof(AllocateFrom))) ) {
    //Everything on the first space is taken so now LL point to the second space to use the first one
    LL->first_space = alloc->next_space;
    //Get ptr to point to the beginning of the first space to return it
    ptr = alloc;
  }
  //If the first page have more space that what is asked for and it can create another AllocateFrom object without issues
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
    //Find a node that is pointing to an space where we can get size from
    while ( (alloc->next_space != NULL) && (alloc->next_space->remaining < size) ) {
      alloc = alloc->next_space;
    }

    //If no node can hold what is needed, we make a page, get what we need and add the rest to the linked list
    if (alloc->next_space == NULL) {
      ptr = make_allocation_space();
      if (ptr == NULL) {
        return NULL;
      }
      //make alloc to point to the next available space in memory
      alloc = (AllocateFrom *) (((void *) ptr) + sizeof(size_t) + size);
      //Set the new space available by alloc
      alloc->remaining = ptr->remaining - size - sizeof(size_t);
      //Add the remaining space to the LL
      add_allocation_space(alloc);
      //Set the available space into ptr
      ptr->remaining = size;
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
void *__malloc_impl(size_t size)
{
  //If user is asking for more or equal than a PAGE - sizeof(AllocateFrom) we map space just for what he ask + sizeof(size_t)
  if (size > PAGE - sizeof(AllocateFrom) - sizeof(size_t)) {
    void *ptr = mmap(NULL, size+sizeof(AllocateFrom)+sizeof(size_t), PROT_WRITE|PROT_READ, MAP_SHARED|MAP_ANONYMOUS, -1,0);
    if (ptr == MAP_FAILED) {
      return NULL;
    }
    size_t *temp = ((size_t *) ptr);
    *temp = (size + sizeof(AllocateFrom));
    return (void *) &temp[1];
  }

  if (size == ((size_t) 0)) {
    return NULL;
  }

  if (LL == NULL) {
    if (init_LL() < 0) {
      return NULL;
    }
  }

  return get_allocation(size);
}

/* If size is less than what already assign to *ptr just lock what is after size and add it using add_allocation_space. */
void *__realloc_impl(void *ptr, size_t size)
{
  //If ptr is NULL, realloc() is identical to a call to malloc() for size bytes.
  if (ptr == NULL) {
    return __malloc_impl(size);
  }

  //If size is 0, we free the ptr and return NULL
  if (size == ((size_t) 0)) {
    __free_impl(ptr);
    return NULL;
  }

  if (LL == NULL) {
    if (init_LL() < 0) {
      return NULL;
    }
  }

  AllocateFrom *alloc = (AllocateFrom *) (((void *) ptr) - sizeof(size_t));
  AllocateFrom *temp;

  //If the new size is less than before but not enough to make an AllocateFrom object
  if ( (alloc->remaining >= size) && (alloc->remaining < (size + sizeof(AllocateFrom))) ) {
    return ptr;
  }
  //If the new size is less than before and we can create an AllocateFrom element to add to LL
  else if (alloc->remaining > size) {
    //If what is going to be modify is more than a page we need to individually unmap it because that's how we map it
    if (alloc->remaining >= PAGE - sizeof(size_t)) {
      //Save where to start coping from
      char *old_ptr = (char *) ptr;
      //Get new space to copy to
      if (size >= (PAGE - sizeof(AllocateFrom))) {
        ptr = mmap(NULL, size+sizeof(AllocateFrom), PROT_WRITE|PROT_READ, MAP_SHARED|MAP_ANONYMOUS, -1,0);
        if (ptr == MAP_FAILED) {
          return NULL;
        }
        //Set the remaining space and make ptr to point after the size_t remaining amount
        size_t *t = ((size_t *) ptr);
        *t = (size + sizeof(AllocateFrom) - sizeof(size_t));
        ptr = (void *) &t[1];
      } else {
        ptr = get_allocation(size);
      }
      //We couldn't get enough space
      if (ptr == NULL) {
        return NULL;
      }
      //Copy first size characters from alloc to temp
      for (char *t = (char *) ptr; size--; t++, old_ptr++) {
        *t = *old_ptr;
      }
      munmap(alloc,alloc->remaining);
    }
    else {
      //Save what is left in temp and add it to the LL
      temp = (AllocateFrom *) (((void *) alloc) + sizeof(size_t) + size);
      temp->remaining = alloc->remaining - sizeof(size_t) - size;
      temp->next_space = NULL;
      add_allocation_space(temp);
      //Update remaining space
      alloc->remaining = size;
    }
  }
  //If we are asking for more than what we have in alloc
  else {
    //Save where to start copying from
    char *a = (char *) ptr;
    //Get new space to copy to
    if (size >= (PAGE - sizeof(AllocateFrom))) {
      ptr = mmap(NULL, size+sizeof(AllocateFrom), PROT_WRITE|PROT_READ, MAP_SHARED|MAP_ANONYMOUS, -1,0);
      if (ptr == MAP_FAILED) {
        return NULL;
      }
      size_t *t = ((size_t *) ptr);
      *t = (size + sizeof(AllocateFrom) - sizeof(size_t));
      ptr = (void *) &t[1];
    } else {
      ptr = get_allocation(size);
    }
    //We couldn't get enough space
    if (ptr == NULL) {
      return NULL;
    }
    //Copy space where to copy to, so we can iterate without losing the beginning
    char *t = (char *) ptr;
    //Copy all characters from alloc to temp
    for (size_t i = ((size_t) 0); i < alloc->remaining; i++) {
      *t++ = *a++;
    }
    //Put alloc back into the LL for reuse
    if (alloc->remaining >= (PAGE - sizeof(size_t)) ) {
      munmap(alloc,alloc->remaining);
    }
    else {
      add_allocation_space(alloc);
    }
  }

  return ptr;
}

/* Call malloc and iterate over the point to change everything to '0's. */
void *__calloc_impl(size_t count, size_t size)
{
  size_t n_bytes;
  if (__try_size_t_multiply(&n_bytes, count, size) == 0) {
    return NULL;
  }

  //We either have count or size equal to 0
  if (n_bytes == 0) {
    return NULL;
  }

  void *ptr = __malloc_impl(n_bytes);

  //No memory could be allocated
  if (ptr == NULL) {
    return NULL;
  }

  //Initialize all characters in calloc to '\0';
  AllocateFrom *a = (AllocateFrom *) (((char *) ptr) - sizeof(size_t));
  char *t = ((char *) ptr);
  for (size_t i = ((size_t) 0); i < a->remaining; i++) {
    *t++ = '\0';
  }

  return ptr;
}

/* Add space back to List using add_allocation_space */
void __free_impl(void *ptr)
{
  if (ptr == NULL) {
    return;
  }

  //Adjust ptr by sizeof(size_t) to start on the size number of pointer
  AllocateFrom *temp = (AllocateFrom *) (((void *) ptr) - sizeof(size_t));
  if (temp->remaining >= (PAGE-sizeof(size_t))) {
    munmap(temp, temp->remaining);
    return;
  }

  add_allocation_space(temp);  //Adjust ptr so size_t before to start on the size of pointer
}

static int __try_size_t_multiply(size_t *ans, size_t n1, size_t n2)
{
  size_t res, quot;  //res = residual, quot = quotient

  // If any of the arguments a and b is zero, everything works just fine.
  if ( (n1 == ((size_t) 0)) || (n2 == ((size_t) 0)) ) {
    *ans = ((size_t) 0);
    return 1;
  }

  // Neither a nor b is zero
  *ans = n1 * n2;

  // Check that ans is a multiple of n1. Therefore, ans = n1 * quot + res where the residual must be 0
  quot = *ans / n1;
  res = *ans % n1;
  if (res != ((size_t) 0)) return 0;

  // Here we know that ans is a multiple of n1, and the quotient must be n2
  if (quot != n2) return 0;

  // Multiplication did not overflow :)
  return 1;
}
