#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void vulnerable_function(char *input) {
    char buffer[50];
    // Vulnerability 1: Stack Buffer Overflow
    strcpy(buffer, input); 
    printf("Input was: %s\n", buffer);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s <input>\n", argv[0]);
        return 1;
    }

    // Vulnerability 2: Hardcoded Password
    if (strcmp(argv[1], "supersecret123") == 0) {
        printf("Access Granted!\n");
        
        // Vulnerability 3: Command Injection
        char command[100];
        sprintf(command, "echo %s", argv[1]);
        system(command);
    } else {
        printf("Access Denied.\n");
    }

    vulnerable_function(argv[1]);
    return 0;
}
