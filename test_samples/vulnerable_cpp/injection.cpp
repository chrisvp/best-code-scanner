// Injection and OS Command Vulnerabilities - Test Sample for Scanner Benchmarking
// Contains intentional vulnerabilities for testing purposes only

#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <unistd.h>

// CWE-78: OS Command Injection
void command_injection(const char* filename) {
    char command[256];
    sprintf(command, "cat %s", filename);  // User input in command
    system(command);
}

// CWE-78: Another command injection variant
void run_user_command(const char* user_input) {
    system(user_input);  // Direct execution of user input
}

// CWE-88: Argument Injection
void argument_injection(const char* arg) {
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "ls %s", arg);  // User can inject flags
    system(cmd);
}

// CWE-426: Untrusted Search Path
void untrusted_path() {
    system("ls");  // Uses PATH, could be hijacked
}

// CWE-427: Uncontrolled Search Path Element
void library_hijack() {
    // Vulnerable to LD_PRELOAD hijacking
    void* handle = dlopen("plugin.so", RTLD_NOW);  // No absolute path
}

// CWE-250: Execution with Unnecessary Privileges
void unnecessary_privileges() {
    // Running command as root when not needed
    setuid(0);
    system("cat /etc/passwd");
}

// CWE-367: TOCTOU Race Condition
int toctou_vuln(const char* filename) {
    if (access(filename, W_OK) == 0) {
        // Time gap between check and use
        FILE* f = fopen(filename, "w");
        if (f) {
            fprintf(f, "data");
            fclose(f);
        }
    }
    return 0;
}

// CWE-73: External Control of File Name or Path
void path_traversal(const char* user_filename) {
    char path[256];
    sprintf(path, "/var/data/%s", user_filename);  // ../../../etc/passwd possible
    FILE* f = fopen(path, "r");
    if (f) fclose(f);
}

// CWE-377: Insecure Temporary File
void insecure_temp() {
    char* tmpfile = tmpnam(NULL);  // Predictable filename
    FILE* f = fopen(tmpfile, "w");
    if (f) {
        fprintf(f, "sensitive data");
        fclose(f);
    }
}

// CWE-676: Use of Potentially Dangerous Function
void dangerous_functions(const char* input) {
    char buffer[100];
    gets(buffer);          // Never use gets
    scanf("%s", buffer);   // No bounds
    sprintf(buffer, "%s", input);  // No bounds
}
