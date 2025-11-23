// Memory Pool Manager - Custom Allocator for Embedded Systems
// Provides efficient memory management with minimal fragmentation

#include <cstdlib>
#include <cstring>
#include <cstdio>
#include <cstdint>
#include <pthread.h>

#define POOL_SIZE (1024 * 1024)  // 1MB pool
#define MIN_BLOCK_SIZE 32
#define MAX_BLOCK_SIZE 4096
#define ALIGNMENT 8
#define MAGIC_ALLOCATED 0xABCD1234
#define MAGIC_FREE 0xDEADBEEF

// Block header structure
struct BlockHeader {
    uint32_t magic;
    size_t size;
    bool is_free;
    BlockHeader* next;
    BlockHeader* prev;
    uint32_t checksum;
};

// Memory pool structure
struct MemoryPool {
    uint8_t* base;
    size_t total_size;
    size_t used_size;
    size_t block_count;
    size_t free_count;
    BlockHeader* free_list;
    BlockHeader* used_list;
    pthread_mutex_t lock;
    bool initialized;
};

// Global memory pool
static MemoryPool g_pool;

// Statistics
struct PoolStats {
    size_t total_allocations;
    size_t total_frees;
    size_t current_allocations;
    size_t peak_usage;
    size_t fragmentation_count;
};

static PoolStats g_stats;

// Forward declarations
static size_t align_size(size_t size);
static uint32_t calculate_header_checksum(BlockHeader* header);
static bool verify_header(BlockHeader* header);
static void coalesce_free_blocks();
static void log_pool(const char* format, ...);

// Initialize the memory pool
int memory_pool_init(size_t pool_size) {
    if (g_pool.initialized) {
        return 0;
    }

    if (pool_size == 0) {
        pool_size = POOL_SIZE;
    }

    // Allocate pool memory
    g_pool.base = (uint8_t*)malloc(pool_size);
    if (!g_pool.base) {
        log_pool("Failed to allocate pool of size %zu", pool_size);
        return -1;
    }

    memset(g_pool.base, 0, pool_size);

    g_pool.total_size = pool_size;
    g_pool.used_size = 0;
    g_pool.block_count = 0;
    g_pool.free_count = 0;

    // Initialize the first free block
    BlockHeader* initial = (BlockHeader*)g_pool.base;
    initial->magic = MAGIC_FREE;
    initial->size = pool_size - sizeof(BlockHeader);
    initial->is_free = true;
    initial->next = NULL;
    initial->prev = NULL;
    initial->checksum = calculate_header_checksum(initial);

    g_pool.free_list = initial;
    g_pool.used_list = NULL;
    g_pool.free_count = 1;

    // Initialize mutex
    pthread_mutex_init(&g_pool.lock, NULL);

    // Initialize stats
    memset(&g_stats, 0, sizeof(g_stats));

    g_pool.initialized = true;

    log_pool("Memory pool initialized with %zu bytes", pool_size);
    return 0;
}

// Shutdown the memory pool
void memory_pool_shutdown() {
    if (!g_pool.initialized) {
        return;
    }

    pthread_mutex_lock(&g_pool.lock);

    if (g_pool.base) {
        free(g_pool.base);
        g_pool.base = NULL;
    }

    g_pool.total_size = 0;
    g_pool.used_size = 0;
    g_pool.free_list = NULL;
    g_pool.used_list = NULL;
    g_pool.initialized = false;

    pthread_mutex_unlock(&g_pool.lock);
    pthread_mutex_destroy(&g_pool.lock);

    log_pool("Memory pool shutdown, peak usage: %zu bytes", g_stats.peak_usage);
}

// Allocate memory from pool
void* memory_pool_alloc(size_t size) {
    if (!g_pool.initialized || size == 0) {
        return NULL;
    }

    size = align_size(size);
    if (size > MAX_BLOCK_SIZE) {
        log_pool("Allocation size %zu exceeds maximum", size);
        return NULL;
    }

    pthread_mutex_lock(&g_pool.lock);

    // Find a suitable free block (first-fit)
    BlockHeader* current = g_pool.free_list;
    BlockHeader* best = NULL;

    while (current) {
        if (!verify_header(current)) {
            log_pool("Corrupted block detected at %p", current);
            pthread_mutex_unlock(&g_pool.lock);
            return NULL;
        }

        if (current->size >= size) {
            if (!best || current->size < best->size) {
                best = current;
            }
        }
        current = current->next;
    }

    if (!best) {
        log_pool("No suitable block found for size %zu", size);
        pthread_mutex_unlock(&g_pool.lock);
        return NULL;
    }

    // Split block if necessary
    size_t remaining = best->size - size;
    if (remaining >= MIN_BLOCK_SIZE + sizeof(BlockHeader)) {
        // Create new free block
        BlockHeader* new_block = (BlockHeader*)((uint8_t*)best + sizeof(BlockHeader) + size);
        new_block->magic = MAGIC_FREE;
        new_block->size = remaining - sizeof(BlockHeader);
        new_block->is_free = true;
        new_block->next = best->next;
        new_block->prev = best->prev;
        new_block->checksum = calculate_header_checksum(new_block);

        if (best->next) {
            best->next->prev = new_block;
        }
        if (best->prev) {
            best->prev->next = new_block;
        } else {
            g_pool.free_list = new_block;
        }

        best->size = size;
        g_pool.free_count++;
    } else {
        // Remove from free list
        if (best->prev) {
            best->prev->next = best->next;
        } else {
            g_pool.free_list = best->next;
        }
        if (best->next) {
            best->next->prev = best->prev;
        }
        g_pool.free_count--;
    }

    // Mark as allocated
    best->magic = MAGIC_ALLOCATED;
    best->is_free = false;

    // Add to used list
    best->next = g_pool.used_list;
    best->prev = NULL;
    if (g_pool.used_list) {
        g_pool.used_list->prev = best;
    }
    g_pool.used_list = best;

    best->checksum = calculate_header_checksum(best);

    // Update stats
    g_pool.used_size += best->size + sizeof(BlockHeader);
    g_pool.block_count++;
    g_stats.total_allocations++;
    g_stats.current_allocations++;

    if (g_pool.used_size > g_stats.peak_usage) {
        g_stats.peak_usage = g_pool.used_size;
    }

    pthread_mutex_unlock(&g_pool.lock);

    void* ptr = (uint8_t*)best + sizeof(BlockHeader);
    return ptr;
}

// Free memory back to pool
void memory_pool_free(void* ptr) {
    if (!g_pool.initialized || !ptr) {
        return;
    }

    pthread_mutex_lock(&g_pool.lock);

    BlockHeader* header = (BlockHeader*)((uint8_t*)ptr - sizeof(BlockHeader));

    // Verify block
    if (!verify_header(header)) {
        log_pool("Invalid free at %p", ptr);
        pthread_mutex_unlock(&g_pool.lock);
        return;
    }

    if (header->is_free) {
        log_pool("Double free detected at %p", ptr);
        pthread_mutex_unlock(&g_pool.lock);
        return;
    }

    // Remove from used list
    if (header->prev) {
        header->prev->next = header->next;
    } else {
        g_pool.used_list = header->next;
    }
    if (header->next) {
        header->next->prev = header->prev;
    }

    // Mark as free
    header->magic = MAGIC_FREE;
    header->is_free = true;

    // Add to free list
    header->next = g_pool.free_list;
    header->prev = NULL;
    if (g_pool.free_list) {
        g_pool.free_list->prev = header;
    }
    g_pool.free_list = header;

    header->checksum = calculate_header_checksum(header);

    // Update stats
    g_pool.used_size -= header->size + sizeof(BlockHeader);
    g_pool.block_count--;
    g_pool.free_count++;
    g_stats.total_frees++;
    g_stats.current_allocations--;

    // Coalesce adjacent free blocks
    coalesce_free_blocks();

    pthread_mutex_unlock(&g_pool.lock);
}

// Reallocate memory
void* memory_pool_realloc(void* ptr, size_t new_size) {
    if (!ptr) {
        return memory_pool_alloc(new_size);
    }

    if (new_size == 0) {
        memory_pool_free(ptr);
        return NULL;
    }

    BlockHeader* header = (BlockHeader*)((uint8_t*)ptr - sizeof(BlockHeader));

    if (!verify_header(header)) {
        return NULL;
    }

    // If same size or smaller, return existing pointer
    new_size = align_size(new_size);
    if (new_size <= header->size) {
        return ptr;
    }

    // Allocate new block
    void* new_ptr = memory_pool_alloc(new_size);
    if (!new_ptr) {
        return NULL;
    }

    // Copy data
    memcpy(new_ptr, ptr, header->size);

    // Free old block
    memory_pool_free(ptr);

    return new_ptr;
}

// Get pool statistics
void memory_pool_get_stats(size_t* total, size_t* used, size_t* free_blocks) {
    if (total) *total = g_pool.total_size;
    if (used) *used = g_pool.used_size;
    if (free_blocks) *free_blocks = g_pool.free_count;
}

// Process callback for each allocated block
int memory_pool_iterate(void (*callback)(void* ptr, size_t size, void* user_data), void* user_data) {
    if (!g_pool.initialized || !callback) {
        return -1;
    }

    pthread_mutex_lock(&g_pool.lock);

    int count = 0;
    BlockHeader* current = g_pool.used_list;

    while (current) {
        void* ptr = (uint8_t*)current + sizeof(BlockHeader);
        callback(ptr, current->size, user_data);
        current = current->next;
        count++;
    }

    pthread_mutex_unlock(&g_pool.lock);
    return count;
}

// Debug: dump pool state
void memory_pool_dump() {
    if (!g_pool.initialized) {
        return;
    }

    pthread_mutex_lock(&g_pool.lock);

    log_pool("=== Memory Pool Dump ===");
    log_pool("Total: %zu bytes", g_pool.total_size);
    log_pool("Used: %zu bytes", g_pool.used_size);
    log_pool("Blocks: %zu allocated, %zu free", g_pool.block_count, g_pool.free_count);

    log_pool("Free list:");
    BlockHeader* current = g_pool.free_list;
    while (current) {
        log_pool("  %p: %zu bytes", current, current->size);
        current = current->next;
    }

    log_pool("Used list:");
    current = g_pool.used_list;
    while (current) {
        log_pool("  %p: %zu bytes", current, current->size);
        current = current->next;
    }

    pthread_mutex_unlock(&g_pool.lock);
}

// Process a block with callback and then free it
// VULNERABILITY: Use-after-free - processes freed memory
int memory_pool_process_and_free(void* ptr, void (*process)(void* data, size_t size)) {
    if (!ptr || !process) {
        return -1;
    }

    BlockHeader* header = (BlockHeader*)((uint8_t*)ptr - sizeof(BlockHeader));

    if (!verify_header(header)) {
        return -1;
    }

    // Free the memory first
    memory_pool_free(ptr);

    // VULNERABILITY: Process the data after it's been freed
    // The memory may have been reallocated or corrupted
    process(ptr, header->size);

    return 0;
}

// Helper functions

static size_t align_size(size_t size) {
    return (size + ALIGNMENT - 1) & ~(ALIGNMENT - 1);
}

static uint32_t calculate_header_checksum(BlockHeader* header) {
    uint32_t checksum = 0;
    checksum ^= header->magic;
    checksum ^= (uint32_t)header->size;
    checksum ^= header->is_free ? 1 : 0;
    return checksum;
}

static bool verify_header(BlockHeader* header) {
    if (!header) {
        return false;
    }

    // Check magic number
    if (header->magic != MAGIC_ALLOCATED && header->magic != MAGIC_FREE) {
        return false;
    }

    // Verify checksum
    uint32_t expected = calculate_header_checksum(header);
    if (header->checksum != expected) {
        return false;
    }

    return true;
}

static void coalesce_free_blocks() {
    // Simplified coalescing - just marks fragmentation
    g_stats.fragmentation_count++;
}

static void log_pool(const char* format, ...) {
    va_list args;
    va_start(args, format);

    char buffer[256];
    vsnprintf(buffer, sizeof(buffer), format, args);

    fprintf(stderr, "[POOL] %s\n", buffer);

    va_end(args);
}
