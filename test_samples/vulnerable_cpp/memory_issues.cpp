// Memory Management Vulnerabilities - Test Sample for Scanner Benchmarking
// Contains intentional vulnerabilities for testing purposes only

#include <cstdlib>
#include <cstring>

// CWE-415: Double Free
void double_free() {
    char* ptr = (char*)malloc(100);
    free(ptr);
    free(ptr);  // Double free vulnerability
}

// CWE-416: Use After Free
char* use_after_free() {
    char* ptr = (char*)malloc(100);
    strcpy(ptr, "test data");
    free(ptr);
    return ptr;  // Returning freed pointer
}

// CWE-401: Memory Leak
void memory_leak(int count) {
    for (int i = 0; i < count; i++) {
        char* buffer = (char*)malloc(1024);
        // Missing free(buffer)
    }
}

// CWE-476: NULL Pointer Dereference
void null_deref(char* ptr) {
    // No null check before dereference
    int len = strlen(ptr);
}

// CWE-690: Unchecked Return Value to NULL Pointer Dereference
void unchecked_malloc() {
    char* ptr = (char*)malloc(1000000000);  // May fail
    strcpy(ptr, "data");  // No null check
}

// CWE-762: Mismatched Memory Management Routines
void mismatched_alloc() {
    char* ptr = new char[100];
    free(ptr);  // Should use delete[]
}

// CWE-763: Release of Invalid Pointer
void invalid_free() {
    char buffer[100];
    free(buffer);  // Freeing stack memory
}

// CWE-825: Expired Pointer Dereference
int* expired_pointer() {
    int local = 42;
    return &local;  // Returning pointer to local variable
}

class Resource {
    char* data;
public:
    Resource() { data = new char[100]; }
    // CWE-772: Missing destructor causes resource leak
    // ~Resource() { delete[] data; }
};

// CWE-467: Use of sizeof() on a Pointer Type
void sizeof_pointer_mistake(char* buffer) {
    char local[256];
    memcpy(local, buffer, sizeof(buffer));  // sizeof(char*) != buffer size
}
