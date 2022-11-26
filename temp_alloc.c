#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include "temp_alloc.h"

/* Make an AllocateFrom item using length and start and add it to the list which does it in ascending order */
void add_allocation_space(void *fsptr, List *LL, AllocateFrom *alloc)
{
  AllocateFrom *temp;
  __off_t temp_off = LL->first_space;
  __off_t alloc_off = ptr_to_off(fsptr, alloc);

  //New space address is less than the first_space in LL
  if (temp_off > alloc_off) {
    /* At this point we know that alloc comes before LL->first_space */
    LL->first_space = alloc_off; //Update first space
    //Check if we can merge LL->first_space and alloc
    if ( (alloc_off + sizeof(size_t) + alloc->remaining) == temp_off ) {
      //Get first pointer
      temp = off_to_ptr(fsptr, temp_off);
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
    temp = off_to_ptr(fsptr, temp_off);
    //Get the last pointer that is in lower memory than alloc
    while ( (temp->next_space != 0) && (temp->next_space < alloc_ptr) ) {
      temp = off_to_ptr(fsptr, temp->next_space);
    }
    temp_off = ptr_to_off(fsptr, temp);

    //At this point, temp_off < alloc_off < temp->next_space. But, there is no guaranty that temp->next_space != 0 (NULL)

    //If temp->next_space != 0 we make alloc_off to point to it and try to merge them
    __off_t after_alloc_off = temp->next_space;
    if (after_alloc_off != 0) {
      //Check if we can merge alloc and after_alloc
      if ( (alloc_off + sizeof(size_t) + alloc->remaining) == after_alloc_off ) {
        Allocate_from *after_alloc = off_to_ptr(fsptr, affter_alloc_off);
        alloc->remaining += sizeof(size_t) + after_alloc->remaining;
        alloc->next_space = after_alloc->next_space;
      }
      //We couldn't merge them
      else {
        alloc->next_space = after_alloc_off;
      }
    }
    //alloc is the last space available in memory ascending order
    else {
      alloc->next_space = 0;
    }
    //Try to merge temp and alloc
    if ( (temp_off + sizeof(size_t) + temp->remaining) == alloc_off ) {
      temp->remaining += sizeof(size_t) + alloc->remaining;
      temp->next_space = alloc->next_space;
    }
    //We couldn't merge them
    else {
      temp->next_space = alloc_off;
    }
  }
}

/* Check if the offset for pref_ptr is 0, if so we get any block for size, otherwise we try to find the block after it and get as much from
 * it as possible and get the rest from the largest block
 */
void *get_allocation(void *fsptr, List *LL, void *org_pref_ptr, size_t *size)
{
  //org_pref_ptr is a ptr (needs -sizeof(size_t)) which we would like to find and use the block after it if it is on free memory
  // There is no guarantee that it its offset is not 0, if so, we don't consider it
  AllocateFrom *org_pref;
  __off_t pref_off = 0;
  AllocateFrom *before_pref;
  int pref_found = 0;

  //Before current space
  __off_t before_temp_off;
  AllocateFrom *before_temp;

  //current space
  __off_t temp_off;
  AllocateFrom *temp;

  //Largest block variables
  __off_t before_largest_off;
  AllocateFrom *before_largest;
  __off_t largest_off;
  AllocateFrom *largest;
  size_t largest_size;

  //Use this ptr if a new block needs to be return
  void *ptr = NULL;

  //If before_temp have an offset of zero we have use all possible space in memory
  if (!before_temp_off) {
    return NULL;
  }

  if (org_pref_ptr != fsptr) {
    org_pref = ((AllocateFrom *) (org_pref_ptr-sizeof(size_t)));
    pref_off = org_pref->next_space;
  }

  //We currently have before_temp as our largest block
  before_temp = off_to_ptr(fsptr, before_temp_off);

  before_largest_off = 0;
  largest_off = before_temp_off;
  largest = before_temp;
  largest_size = before_temp->remaining;

  //Get next space
  temp_off = before_temp->next_space;
  temp = off_to_ptr(fsptr, temp_off);

  //Iterate the list until the first block that can hold size and the block after pref_ptr is found (or pass because it is not there)
  while (temp_off != 0) {
    //Check if temp_off is the prefer block that we are looking for or if temp have more space available than the previous largest
    if ( (pref_off == temp_off) || (temp->remaining > largest_size) ) {
      //If temp_off is pref we would not like to update largest space so we have two places to get space from
      if (pref_off == temp_off) {
        //pref_found was successfully found
        pref_found = 1;
        before_pref = before_temp;
      }
      //Update largest space
      else {
        before_largest_off = before_temp_off;
        before_largest = before_temp;
        largest_off = temp_off;
        largest = temp;
        largest_size = temp->remaining;
      }
    }
    //Update pointers to next space
    before_temp_off = temp_off;
    before_temp = temp;
    temp_off = temp->next_space;
    temp = off_to_ptr(fsptr, temp_off);
  }

  //If the prefer block was found we get as much as we can from it until size or until we run out of bytes available from it
  if (pref_found) {
    //Check if you can get all size bytes from the prefer block
    if (pref->remaining >= size) {
      //Check if we can make an AllocateFrom object with the remaining space
      if (pref->reminaing + sizeof(AllocateFrom) > size) {
        //Set original pref with final total size
        org_pref->remaining += size;
        //Make the new AllocateFrom object
        temp = ((void *) pref) + size;
        temp->remaining = pref->remaining - size;
        temp->next_space = pref->next_space;
        //Update pointers to add temp into list of free blocks
        before_pref->next_space = pref_off + size;
      }
      //We can't make a AllocateFrom object
      else {
        //
      }
      *size = 0;
    }
    //We couldn't got everything from the prefer block so we get as much as we can
    else {
      //TODO
    }
  }

  //If size is still not 0 we get as much as we can from it or until size is 0
  if (*size != 0) {
    //
  }

  //We suppose to return the new block address if a new block outside the prefer one was needed
  return ptr;
}

/* If size is zero, return NULL. Otherwise, call get_allocation_space with size. */
void *__malloc_impl(void *fsptr, size_t size)
{
  if (size == ((size_t) 0)) {
    return NULL;
  }

  return get_allocation(void *fsptr, get_free_memory_ptr(fsptr), fsptr, size);
}

/* If size is less than what already assign to *ptr just lock what is after size and add it using add_allocation_space. */
void *__realloc_impl(void *fsptr, void *orig_ptr, size_t *size)
{
  //If size is 0, we free the ptr and return NULL
  if (*size == ((size_t) 0)) {
    __free_impl(fsptr, orig_ptr);
    return NULL;
  }

  List *LL = get_free_memory_ptr(fsptr);

  //If ptr is fsptr if the offset was 0 (kind of pointing to null), realloc() is identical to a call to malloc() for size bytes.
  if (orig_ptr == fsptr) {
    //fsptr because we don't have a preference over the location of the pointer that would be returned, (offset of 0).
    return get_allocation(fsptr, LL, fsptr, size);
  }

  AllocateFrom *alloc = (AllocateFrom *) (((void *) orig_ptr) - sizeof(size_t));
  AllocateFrom *temp;
  void *new_ptr;

  //If the new size is less than before but not enough to make an AllocateFrom object
  if ( (alloc->remaining >= *size) && (alloc->remaining < (*size + sizeof(AllocateFrom))) ) {
    //No new ptr was created
    new_ptr = orig_ptr;
  }
  //If the new size is less than before and we can create an AllocateFrom element to add to LL
  else if (alloc->remaining > *size) {
    //Save what is left in temp and add it to the LL
    temp = (AllocateFrom *) (orig_ptr + *size);
    temp->remaining = alloc->remaining - *size - sizeof(size_t);
    temp->next_space = fsptr; //Offset of zero
    add_allocation_space(fsptr, LL, temp);
    //Update remaining space
    alloc->remaining = *size;
    //No new ptr was created
    new_ptr = orig_ptr;
  }
  //If we are asking for more than what we have in alloc
  else {
    //Get new space to copy to
    // fsptr because we don't have a preference over the location of the pointer that would be returned, (offset of 0).
    new_ptr = get_allocation(fsptr, LL, fsptr, size);
    //We couldn't get enough space
    if (new_ptr == NULL) {
      return NULL;
    }
    //Copy what was inside orig_ptr into new_ptr
    memcpy(new_ptr, orig_ptr, alloc->remaining);
    //Free the space of the original pointer
    add_allocation_space(fsptr, LL, alloc);
  }

  return new_ptr;
}

