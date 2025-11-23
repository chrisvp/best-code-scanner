// Integer Vulnerabilities - Test Sample for Scanner Benchmarking
// Contains intentional vulnerabilities for testing purposes only

#include <cstdlib>
#include <cstdint>
#include <climits>

// CWE-190: Integer Overflow
int integer_overflow(int a, int b) {
    return a * b;  // May overflow without check
}

// CWE-191: Integer Underflow
unsigned int integer_underflow(unsigned int a, unsigned int b) {
    return a - b;  // May underflow if b > a
}

// CWE-681: Incorrect Conversion between Numeric Types
void incorrect_conversion(size_t size) {
    int buffer_size = size;  // Truncation if size > INT_MAX
    char* buffer = (char*)malloc(buffer_size);
    free(buffer);
}

// CWE-195: Signed to Unsigned Conversion Error
void signed_unsigned_error(int index, char* array) {
    if (index < 10) {  // Negative index passes check
        array[index] = 'x';  // But becomes large positive when used
    }
}

// CWE-194: Unexpected Sign Extension
int sign_extension(char c) {
    int value = c;  // Char may be signed, causing sign extension
    return value;
}

// CWE-369: Divide By Zero
int divide_by_zero(int a, int b) {
    return a / b;  // No check for b == 0
}

// CWE-682: Incorrect Calculation
void* incorrect_alloc_calc(int count, int size) {
    // Multiplication may overflow before allocation
    return malloc(count * size);
}

// CWE-128: Wrap-around Error
void wrap_around(size_t offset) {
    size_t result = offset + 100;  // May wrap around
    char* buffer = (char*)malloc(result);
    free(buffer);
}

// CWE-680: Integer Overflow to Buffer Overflow
void int_overflow_to_buffer_overflow(unsigned int size) {
    unsigned int total = size + 10;  // May overflow
    char* buffer = (char*)malloc(total);
    if (buffer) {
        for (unsigned int i = 0; i < size + 10; i++) {
            buffer[i] = 'A';  // Write past allocated size if overflow
        }
        free(buffer);
    }
}

// CWE-839: Numeric Range Comparison Without Minimum Check
void no_minimum_check(int index, int array[], int size) {
    if (index < size) {  // No check for index >= 0
        array[index] = 0;
    }
}

// CWE-192: Integer Coercion Error
void coercion_error(long long big_value) {
    int small_value = big_value;  // Loss of data
    printf("%d\n", small_value);
}
