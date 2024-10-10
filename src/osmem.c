// SPDX-License-Identifier: BSD-3-Clause

#include "osmem.h"
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include "block_meta.h"

#define MMAP_THRESHOLD (128 * 1024) // 128KB
#define MMAP_THRESHOLDCALLOC 4080
#define ALIGNMENT 8
#define ALIGN(size) (((size) + (ALIGNMENT-1)) & ~(ALIGNMENT-1))
#define META_ALIGN ALIGN(sizeof(struct block_meta))

struct block_meta *heap_start;
size_t remaining_heap_size = MMAP_THRESHOLD;

size_t total_size(size_t size)
{
	/* block_meta + padding + payload + padding */
	return META_ALIGN + ALIGN(size);
}

void *preallocate(size_t size)
{
	/* preallocating MMAP_THRESHOLD bytes */
	heap_start = (struct block_meta *)sbrk(MMAP_THRESHOLD);
	DIE(heap_start == (void *) -1, "Preallocation failed");

	/* creating the first block in the list */
	struct block_meta *first_block = heap_start;

	first_block->size = size;
	first_block->status = STATUS_ALLOC;
	first_block->prev = NULL;
	first_block->next = NULL;

	/* returning the address where the payload starts,
	 * after the struct block_meta + padding
	 */
	return (char *)first_block + META_ALIGN;
}

struct block_meta *find_best_block_heap(size_t size)
{
	/* searching for the best block by two criteria:
	 * 1. it has to be free (STATUS_FREE)
	 * 2. the size of the block has to be the closest to
	 * the total size needed for the block
	 */
	/* if it doesn't find anything, the function returns NULL,
	 * which means a new block will have to be allocated
	 */
	struct block_meta *current = heap_start;
	struct block_meta *best_block = NULL;

	while (current) {
		if (current->status == STATUS_FREE &&
			total_size(current->size) >= total_size(size)) {
			if (best_block == NULL || current->size < best_block->size)
				/* trying to find the best fit for the block's size */
				best_block = current;
		}
		current = current->next;
	}

	return best_block;
}

void *create_new_block(size_t size)
{
	struct block_meta *current = heap_start;
	struct block_meta *last_block = NULL;

	/* finding the last block in the list */
	while (current) {
		last_block = current;
		current = current->next;
	}

	/* allocating the memory */
	last_block = (struct block_meta *)sbrk(total_size(size));
	DIE(last_block == (void *) -1, "Sbrk failed");

	last_block->size = size;
	last_block->status = STATUS_ALLOC;
	last_block->next = NULL;

	return (char *)last_block + META_ALIGN;
}

void *split_block(struct block_meta *block, size_t size)
{
	/* splitting the block at the address where the allocated
	 * block doesn't have access and marking the remaining memory
	 * as free
	 */
	struct block_meta *split_block = (struct block_meta *)((char *)block +
									 total_size(size));

	split_block->next = block->next;
	block->next = split_block;

	split_block->size = block->size - total_size(size);
	block->size = size;

	block->status = STATUS_ALLOC;
	split_block->status = STATUS_FREE;

	return (char *)block + META_ALIGN;
}

void *memory_management_for_free_block(struct block_meta *last_block,
									  size_t size)
{
	if (total_size(size) > total_size(last_block->size)) {
		/* allocating more memory as the block needs to be expanded */
		struct block_meta *expanded_block = (struct block_meta *)sbrk
									(ALIGN(size) - ALIGN(last_block->size));
		DIE(expanded_block == (void *) -1, "Sbrk failed");

		remaining_heap_size -= total_size(last_block->size);

		last_block->size = size;
		last_block->status = STATUS_ALLOC;
	} else if (total_size(size) == total_size(last_block->size)) {
		/* the block is a perfect fit, so it's only necessary to fill in
		 * the metadata of the block
		 */
		remaining_heap_size -= total_size(last_block->size);

		last_block->size = size;
		last_block->status = STATUS_ALLOC;
	} else {
		/* the block is bigger than the size needed, so it will be split */
		//printf("aici");
		remaining_heap_size -= total_size(size);
		return split_block(last_block, size);
	}

	return (char *)last_block + META_ALIGN;
}

void coalesce(void)
{
	struct block_meta *current = heap_start;

	/* going through the list of blocks to find adjacent free blocks */
	while (current != NULL && current->next != NULL) {
		if (current->status == STATUS_FREE && current->next->status == STATUS_FREE) {
			current->size += total_size(current->next->size);

			struct block_meta *next_block = current->next;

			current->next = next_block->next;
		} else {
			current = current->next;
		}
	}
}

void *os_malloc(size_t size)
{
	if (size == 0)
		return NULL;

	size_t total = total_size(size);

	if (total <= MMAP_THRESHOLD && remaining_heap_size >= total) {
		/* preallocation and then using the memory allocated */
		remaining_heap_size -= total;
		if (!heap_start)
			return preallocate(size);

		struct block_meta *block = find_best_block_heap(size);

		if (!block)
			return create_new_block(size);

		if (block->size > total)
			return split_block(block, size);

		/* if the block found is a perfect fit, it just has
		 * to be marked as allocated
		 */
		block->status = STATUS_ALLOC;

		return (char *)block + META_ALIGN;
	} else if (total < MMAP_THRESHOLD) {
		/* using brk for memory allocation that's smaller than MMAP_THRESHOLD */
		struct block_meta *current = heap_start;
		struct block_meta *last_block = NULL;

		while (current) {
			last_block = current;
			current = current->next;
		}

		if (last_block->status == STATUS_ALLOC) {
			/* alloc a new block */
			last_block->next = (struct block_meta *)sbrk(total);
			DIE(last_block->next == (void *) -1, "Sbrk failed");

			last_block->next->size = size;
			last_block->next->status = STATUS_ALLOC;
			last_block->next->next = NULL;

			return (char *)last_block->next + META_ALIGN;
		} else if (last_block->status == STATUS_FREE) {
			return memory_management_for_free_block(last_block, size);
		}
	} else {
		/* using mmap for memory allocation that's bigger than MMAP_THRESHOLD */
		struct block_meta *map_block = mmap(NULL, total, PROT_READ | PROT_WRITE,
									   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		DIE(map_block == MAP_FAILED, "Mmap failed");

		map_block->size = size;
		map_block->status = STATUS_MAPPED;

		return (char *)map_block + META_ALIGN;
	}
	return NULL;
}

void os_free(void *ptr)
{
	if (ptr == NULL)
		return;

	/* finding the address where the metadata begins */
	struct block_meta *block_free = (struct block_meta *)ptr - 1;

	if (block_free->status == STATUS_ALLOC) {
		/* if the block was allocated with brk, only marking
		 * it as free and it can be reused later
		 */
		block_free->status = STATUS_FREE;
		remaining_heap_size += total_size(block_free->size);
	} else if (block_free->status == STATUS_MAPPED) {
		/* if the block was allocated with mmap, it won't be reused */
		munmap(block_free, total_size(block_free->size));
	}

	coalesce();
}

void *os_calloc(size_t nmemb, size_t size)
{
	size_t total = nmemb * size;

	if (total == 0)
		return NULL;

	total = total_size(total);

	if (total > MMAP_THRESHOLDCALLOC) {
		/* allocating with mmap for chunks of memory
		 * bigger than the page size
		 */
		struct block_meta *map_block = mmap(NULL, total, PROT_READ | PROT_WRITE,
									   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		DIE(map_block == MAP_FAILED, "Mmap failed");

		map_block->size = ALIGN(size * nmemb);
		map_block->status = STATUS_MAPPED;
		map_block->next = NULL;

		return (char *)map_block + META_ALIGN;
	}

	/* malloc will use brk calls for chunks smaller than the page size */
	void *ptr = os_malloc(size * nmemb);

	DIE(!ptr, "Malloc failed");

	/* calloc initialises the memory allocated with 0 */
	memset(ptr, 0, size * nmemb);

	return ptr;
}

void *os_realloc(void *ptr, size_t size)
{
	if (!ptr)
		return os_malloc(size);

	if (size == 0) {
		os_free(ptr);
		return NULL;
	}
	/* finding the block at the address of the pointer */
	struct block_meta *old_block = (struct block_meta *)ptr - 1;

	size_t old_size = old_block->size;

	/* if the size is equal to the one before, nothing changes */
	if (size == old_size)
		return ptr;

	/* declaring the status of the block as free so malloc can
	 * use the old block as well when searching for the best fit
	 * note: this isn't a good solution, but it solves some cases
	 */
	old_block->status = STATUS_FREE;
	void *new_ptr = os_malloc(size);

	if (!new_ptr)
		return NULL;

	/* if the block is smaller after the allocation */
	if (size < old_size)
		old_size = size;

	/* copying the data from the old pointer to the new one */
	memmove(new_ptr, ptr, old_size);
	os_free(ptr);

	return new_ptr;
}
