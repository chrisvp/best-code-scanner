// Buffer Overflow Vulnerabilities - Test Sample for Scanner Benchmarking
// Contains intentional vulnerabilities for testing purposes only

#include <cstring>
#include <cstdio>
#include <cstdlib>

// CWE-120: Buffer Copy without Checking Size of Input
void vulnerable_strcpy(const char* input) {
    char buffer[64];
    strcpy(buffer, input);  // No bounds checking
    printf("Copied: %s\n", buffer);
}

// CWE-121: Stack-based Buffer Overflow
void stack_overflow(const char* data) {
    char local_buffer[128];
    sprintf(local_buffer, "User input: %s", data);  // Format string with unbounded input
}

// CWE-122: Heap-based Buffer Overflow
void heap_overflow(size_t size, const char* data) {
    char* heap_buffer = (char*)malloc(100);
    memcpy(heap_buffer, data, size);  // No check if size > 100
    free(heap_buffer);
}

// CWE-134: Use of Externally-Controlled Format String
void format_string_vuln(const char* user_input) {
    printf(user_input);  // User controls format string
}

// CWE-787: Out-of-bounds Write
void oob_write(int index, int value) {
    int array[10];
    array[index] = value;  // No bounds check on index
}

// CWE-125: Out-of-bounds Read
int oob_read(int index) {
    int array[10] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9};
    return array[index];  // No bounds check on index
}

// CWE-131: Incorrect Calculation of Buffer Size
void wrong_buffer_size(const char* input) {
    size_t len = strlen(input);
    char* buffer = (char*)malloc(len);  // Should be len + 1 for null terminator
    strcpy(buffer, input);
    free(buffer);
}

// CWE-170: Improper Null Termination
void missing_null_term(char* dest, const char* src, size_t n) {
    strncpy(dest, src, n);  // strncpy doesn't guarantee null termination
    // Missing: dest[n-1] = '\0';
}

int main() {
    char input[256];
    printf("Enter data: ");
    gets(input);  // CWE-242: Use of Inherently Dangerous Function

    vulnerable_strcpy(input);
    return 0;
}
