/*
 * mm-explicit.c - The best malloc package EVAR!
 *
 * TODO (bug): Uh..this is an implicit list???
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "memlib.h"
#include "mm.h"

/** The required alignment of heap payloads */
const size_t ALIGNMENT = 2 * sizeof(size_t);

/** The layout of each block allocated on the heap */
typedef struct {
    /** The size of the block and whether it is allocated (stored in the low bit) */
    size_t header;
    /**
     * We don't know what the size of the payload will be, so we will
     * declare it as a zero-length array.  This allow us to obtain a
     * pointer to the start of the payload.
     */
    uint8_t payload[];
} block_t;
// block + size = next
// block + size - 8 = footer

// store nodes in payload
// recursive node struct

typedef struct node_t {
    struct node_t *prev;
    struct node_t *next;
} node_t;

typedef struct {
    size_t footer;
} footer_t;

/** The first and last blocks on the heap */
static block_t *mm_heap_first = NULL;
static block_t *mm_heap_last = NULL;

/** Head of linked list of free blocks */
node_t *head = NULL;

/** Rounds up `size` to the nearest multiple of `n` */
static size_t round_up(size_t size, size_t n) {
    return (size + (n - 1)) / n * n;
}

/** Set's a block's header with the given size and allocation state */
static void set_header_and_footer(block_t *block, size_t size, bool is_allocated) {
    size_t hdr_ftr = size | is_allocated;
    block->header = hdr_ftr;
    footer_t *ftr = (void *) block + size - sizeof(size_t);
    // printf("%zu\n", (size_t) ftr);
    ftr->footer = hdr_ftr;
}

/** Extracts a block's size from its header */
static size_t get_size(block_t *block) {
    return block->header & ~1;
}

/** Extracts a block's size from its footer */
static size_t get_size_ftr(footer_t *ftr) {
    return ftr->footer & ~1;
}

/** Extracts a block's allocation state from its header */
static bool is_allocated(block_t *block) {
    return block->header & 1;
}

/** Extracts a block's allocation state from its footer */
static bool is_allocated_ftr(footer_t *ftr) {
    return ftr->footer & 1;
}

/** Gets the header corresponding to a given payload pointer */
static block_t *block_from_payload(void *ptr) {
    return ptr - offsetof(block_t, payload);
}

/** Add free block to head of free list */
// take in block t
static void add_to_free(block_t *to_add) {
    node_t *node = (void *) to_add + sizeof(size_t);
    if (head == NULL) {
        head = node;
        head->prev = NULL;
        head->next = NULL;
    }
    else {
        node_t *next_free = head;
        head = node;
        head->next = next_free;
        head->next->prev = head;
        head->prev = NULL;
    }
}

/** Remove block from free list */
static void remove_from_free(block_t *to_remove) {
    node_t *node = (void *) to_remove + sizeof(size_t);
    if (head == node) {
        if (head->next == NULL) {
            head = NULL;
        }
        else {
            head = node->next;
            head->prev = NULL;
        }
    }
    else if (node->next == NULL) {
        node->prev->next = NULL;
    }
    else {
        node->prev->next = node->next;
        node->next->prev = node->prev;
    }
}

/** Coalesce adjacent free blocks */
static void coalesce(block_t *curr) {
    size_t curr_size = get_size(curr);
    if (curr != mm_heap_last) {
        block_t *right = (void *) curr + curr_size;
        if (!is_allocated(right) && !is_allocated(curr)) {
            size_t right_size = get_size(right);
            set_header_and_footer(curr, curr_size + right_size, false);
            if (right == mm_heap_last) {
                mm_heap_last = curr;
            }
            remove_from_free(right);
        }
    }
    if (curr != mm_heap_first) {
        curr_size = get_size(curr);
        footer_t *left = (void *) curr - sizeof(size_t);
        size_t left_size = get_size_ftr(left);
        block_t *left_block = (void *) curr - left_size;
        if (!is_allocated_ftr(left) && !is_allocated(curr)) {
            set_header_and_footer(left_block, curr_size + left_size, false);
            if (curr == mm_heap_last) {
                mm_heap_last = left_block;
            }
            remove_from_free(curr);
        }
    }
}

/**
 * Finds the first free block in the heap with at least the given size.
 * If no block is large enough, returns NULL.
 */
static block_t *find_fit(size_t size) {
    // Traverse free blocks using explicit list
    node_t *curr_ptr = head;
    while (curr_ptr != NULL) {
        block_t *curr = block_from_payload((void *) curr_ptr);
        node_t *next_free = curr_ptr->next;
        if (get_size(curr) >= size + 4 * sizeof(size_t)) {
            size_t old_size = get_size(curr);
            block_t *next = (void *) curr + size;

            set_header_and_footer(curr, size, true);
            set_header_and_footer(next, old_size - size, false);

            add_to_free(next);

            if (curr == mm_heap_last) {
                mm_heap_last = next;
            }
            remove_from_free(curr);
            return curr;
        }
        else if (get_size(curr) >= size) {
            remove_from_free(curr);
            return curr;
        }
        curr_ptr = next_free;
    }

    return NULL;
}

/**
 * mm_init - Initializes the allocator state
 */
bool mm_init(void) {
    // We want the first payload to start at ALIGNMENT bytes from the start of the heap
    void *padding = mem_sbrk(ALIGNMENT - sizeof(block_t));
    if (padding == (void *) -1) {
        return false;
    }

    // Initialize the heap with no blocks
    mm_heap_first = NULL;
    mm_heap_last = NULL;

    head = NULL;
    return true;
}

/**
 * mm_malloc - Allocates a block with the given size
 */
void *mm_malloc(size_t size) {
    // The block must have enough space for a header and be 16-byte aligned
    size = round_up(sizeof(block_t) + size + sizeof(size_t), ALIGNMENT);

    // If there is a large enough free block, use it
    block_t *block = find_fit(size);
    if (block != NULL) {
        set_header_and_footer(block, get_size(block), true);
        return block->payload;
    }

    // Otherwise, a new block needs to be allocated at the end of the heap
    block = mem_sbrk(size);
    if (block == (void *) -1) {
        return NULL;
    }

    // Update mm_heap_first and mm_heap_last since we extended the heap
    if (mm_heap_first == NULL) {
        mm_heap_first = block;
    }
    mm_heap_last = block;

    // Initialize the block with the allocated size
    set_header_and_footer(block, size, true);
    // footer_t *ftr = (void *)block + get_size(block) - sizeof(size_t);
    // printf("header:%zu \nfooter: %zu\n", block->header, (size_t) ftr->footer);
    return block->payload;
}

/**
 * mm_free - Releases a block to be reused for future allocations
 */
void mm_free(void *ptr) {
    // mm_free(NULL) does nothing
    if (ptr == NULL) {
        return;
    }

    // Mark the block as unallocated
    block_t *block = block_from_payload(ptr);
    set_header_and_footer(block, get_size(block), false);
    // footer_t *ftr = (void *)block + get_size(block) - sizeof(size_t);
    // printf("header:%zu \nfooter: %zu\n", block->header, (size_t) ftr->footer);

    // Make block new head of list
    add_to_free(block);

    coalesce(block);
}

/**
 * mm_realloc - Change the size of the block by mm_mallocing a new block,
 *      copying its data, and mm_freeing the old block.
 */
void *mm_realloc(void *old_ptr, size_t size) {
    if (old_ptr == NULL) {
        return mm_malloc(size);
    }
    if (size == 0) {
        mm_free(old_ptr);
        return NULL;
    }

    block_t *block = block_from_payload(old_ptr);
    size_t old_size = get_size(block);

    if (size <= old_size - 2 * sizeof(block_t)) {
        return old_ptr;
    }
    void *new_ptr = mm_malloc(size);
    memcpy(new_ptr, old_ptr, old_size);
    mm_free(old_ptr);
    return new_ptr;
}

/**
 * mm_calloc - Allocate the block and set it to zero.
 */
void *mm_calloc(size_t nmemb, size_t size) {
    void *ptr = mm_malloc(nmemb * size);
    memset(ptr, 0, size);
    return ptr;
}

/**
 * mm_checkheap - So simple, it doesn't need a checker!
 */
void mm_checkheap(void) {
}
