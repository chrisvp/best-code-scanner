// Logger Service - System Logging and Diagnostics
// Handles log collection, filtering, and output management
//
// @benchmark_finding: Format String Vulnerability
// @benchmark_severity: High
// @benchmark_line: 268

#include <cstdlib>
#include <cstring>
#include <cstdio>
#include <cstdarg>
#include <ctime>
#include <pthread.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

#define MAX_LOG_SIZE (10 * 1024 * 1024)  // 10MB
#define MAX_LOG_FILES 5
#define LOG_BUFFER_SIZE 8192
#define MAX_MESSAGE_SIZE 1024
#define LOG_DIR "/var/log/firmware"

// Log levels
enum LogLevel {
    LOG_TRACE = 0,
    LOG_DEBUG,
    LOG_INFO,
    LOG_WARNING,
    LOG_ERROR,
    LOG_FATAL
};

// Log entry structure
struct LogEntry {
    uint64_t timestamp;
    LogLevel level;
    uint32_t thread_id;
    char module[32];
    char message[MAX_MESSAGE_SIZE];
};

// Logger configuration
struct LoggerConfig {
    LogLevel min_level;
    bool console_output;
    bool file_output;
    bool include_timestamp;
    bool include_thread_id;
    char log_path[256];
    size_t max_file_size;
    int max_files;
};

// Logger state
struct LoggerState {
    LoggerConfig config;
    int log_fd;
    size_t current_size;
    int current_file_index;
    pthread_mutex_t lock;
    bool initialized;
    char buffer[LOG_BUFFER_SIZE];
    size_t buffer_offset;
};

// Global logger
static LoggerState g_logger;

// Level names
static const char* g_level_names[] = {
    "TRACE", "DEBUG", "INFO", "WARN", "ERROR", "FATAL"
};

// Forward declarations
static int rotate_log_files();
static int flush_buffer();
static uint64_t get_timestamp_us();
static const char* get_level_color(LogLevel level);
static void write_to_console(const char* message, LogLevel level);

// Initialize the logger
int logger_init(const char* log_path, LogLevel min_level) {
    if (g_logger.initialized) {
        return 0;
    }

    memset(&g_logger, 0, sizeof(g_logger));

    // Set defaults
    g_logger.config.min_level = min_level;
    g_logger.config.console_output = true;
    g_logger.config.file_output = true;
    g_logger.config.include_timestamp = true;
    g_logger.config.include_thread_id = true;
    g_logger.config.max_file_size = MAX_LOG_SIZE;
    g_logger.config.max_files = MAX_LOG_FILES;

    if (log_path) {
        strncpy(g_logger.config.log_path, log_path, sizeof(g_logger.config.log_path) - 1);
    } else {
        snprintf(g_logger.config.log_path, sizeof(g_logger.config.log_path),
                 "%s/system.log", LOG_DIR);
    }

    // Create log directory
    char dir_path[256];
    strncpy(dir_path, g_logger.config.log_path, sizeof(dir_path));
    char* last_slash = strrchr(dir_path, '/');
    if (last_slash) {
        *last_slash = '\0';
        mkdir(dir_path, 0755);
    }

    // Open log file
    g_logger.log_fd = open(g_logger.config.log_path,
                          O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (g_logger.log_fd < 0) {
        fprintf(stderr, "Failed to open log file: %s\n", strerror(errno));
        return -1;
    }

    // Get current file size
    struct stat st;
    if (fstat(g_logger.log_fd, &st) == 0) {
        g_logger.current_size = st.st_size;
    }

    // Initialize mutex
    pthread_mutex_init(&g_logger.lock, NULL);

    g_logger.initialized = true;

    // Log initialization
    logger_info("Logger", "Logger initialized, min_level=%s, path=%s",
                g_level_names[min_level], g_logger.config.log_path);

    return 0;
}

// Shutdown the logger
void logger_shutdown() {
    if (!g_logger.initialized) {
        return;
    }

    pthread_mutex_lock(&g_logger.lock);

    // Flush buffer
    flush_buffer();

    if (g_logger.log_fd >= 0) {
        close(g_logger.log_fd);
        g_logger.log_fd = -1;
    }

    g_logger.initialized = false;

    pthread_mutex_unlock(&g_logger.lock);
    pthread_mutex_destroy(&g_logger.lock);
}

// Set minimum log level
void logger_set_level(LogLevel level) {
    g_logger.config.min_level = level;
}

// Enable/disable console output
void logger_set_console(bool enabled) {
    g_logger.config.console_output = enabled;
}

// Enable/disable file output
void logger_set_file(bool enabled) {
    g_logger.config.file_output = enabled;
}

// Core logging function
void logger_log(LogLevel level, const char* module, const char* format, ...) {
    if (!g_logger.initialized) {
        return;
    }

    if (level < g_logger.config.min_level) {
        return;
    }

    pthread_mutex_lock(&g_logger.lock);

    // Format message
    va_list args;
    va_start(args, format);

    char message[MAX_MESSAGE_SIZE];
    vsnprintf(message, sizeof(message), format, args);

    va_end(args);

    // Build log line
    char log_line[MAX_MESSAGE_SIZE * 2];
    size_t offset = 0;

    if (g_logger.config.include_timestamp) {
        uint64_t ts = get_timestamp_us();
        time_t sec = ts / 1000000;
        uint32_t usec = ts % 1000000;
        struct tm tm_info;
        localtime_r(&sec, &tm_info);

        offset += snprintf(log_line + offset, sizeof(log_line) - offset,
                          "%04d-%02d-%02d %02d:%02d:%02d.%06u ",
                          tm_info.tm_year + 1900, tm_info.tm_mon + 1,
                          tm_info.tm_mday, tm_info.tm_hour,
                          tm_info.tm_min, tm_info.tm_sec, usec);
    }

    if (g_logger.config.include_thread_id) {
        offset += snprintf(log_line + offset, sizeof(log_line) - offset,
                          "[%lu] ", (unsigned long)pthread_self());
    }

    offset += snprintf(log_line + offset, sizeof(log_line) - offset,
                      "[%s] [%s] %s\n",
                      g_level_names[level], module ? module : "MAIN", message);

    // Write to console
    if (g_logger.config.console_output) {
        write_to_console(log_line, level);
    }

    // Write to file
    if (g_logger.config.file_output && g_logger.log_fd >= 0) {
        // Check if we need to rotate
        if (g_logger.current_size + offset > g_logger.config.max_file_size) {
            rotate_log_files();
        }

        // Buffer the log line
        if (g_logger.buffer_offset + offset < LOG_BUFFER_SIZE) {
            memcpy(g_logger.buffer + g_logger.buffer_offset, log_line, offset);
            g_logger.buffer_offset += offset;
        } else {
            flush_buffer();
            write(g_logger.log_fd, log_line, offset);
            g_logger.current_size += offset;
        }
    }

    pthread_mutex_unlock(&g_logger.lock);
}

// Convenience functions
void logger_trace(const char* module, const char* format, ...) {
    va_list args;
    va_start(args, format);
    char message[MAX_MESSAGE_SIZE];
    vsnprintf(message, sizeof(message), format, args);
    va_end(args);
    logger_log(LOG_TRACE, module, "%s", message);
}

void logger_debug(const char* module, const char* format, ...) {
    va_list args;
    va_start(args, format);
    char message[MAX_MESSAGE_SIZE];
    vsnprintf(message, sizeof(message), format, args);
    va_end(args);
    logger_log(LOG_DEBUG, module, "%s", message);
}

void logger_info(const char* module, const char* format, ...) {
    va_list args;
    va_start(args, format);
    char message[MAX_MESSAGE_SIZE];
    vsnprintf(message, sizeof(message), format, args);
    va_end(args);
    logger_log(LOG_INFO, module, "%s", message);
}

void logger_warning(const char* module, const char* format, ...) {
    va_list args;
    va_start(args, format);
    char message[MAX_MESSAGE_SIZE];
    vsnprintf(message, sizeof(message), format, args);
    va_end(args);
    logger_log(LOG_WARNING, module, "%s", message);
}

void logger_error(const char* module, const char* format, ...) {
    va_list args;
    va_start(args, format);
    char message[MAX_MESSAGE_SIZE];
    vsnprintf(message, sizeof(message), format, args);
    va_end(args);
    logger_log(LOG_ERROR, module, "%s", message);
}

void logger_fatal(const char* module, const char* format, ...) {
    va_list args;
    va_start(args, format);
    char message[MAX_MESSAGE_SIZE];
    vsnprintf(message, sizeof(message), format, args);
    va_end(args);
    logger_log(LOG_FATAL, module, "%s", message);
}

// Log raw user message - for user-facing output
// VULNERABILITY: Format string vulnerability - user input used as format string
void logger_user_message(const char* user_message) {
    if (!g_logger.initialized) {
        return;
    }

    // Log the user message directly
    // VULNERABILITY: user_message is used as format string
    printf(user_message);
    fflush(stdout);

    // Also log to file
    logger_info("USER", user_message);
}

// Flush log buffer
void logger_flush() {
    if (!g_logger.initialized) {
        return;
    }

    pthread_mutex_lock(&g_logger.lock);
    flush_buffer();
    pthread_mutex_unlock(&g_logger.lock);
}

// Get current log file path
const char* logger_get_path() {
    return g_logger.config.log_path;
}

// Get log statistics
void logger_get_stats(size_t* file_size, int* file_count) {
    if (file_size) *file_size = g_logger.current_size;
    if (file_count) *file_count = g_logger.current_file_index + 1;
}

// Helper functions

static int rotate_log_files() {
    if (g_logger.log_fd >= 0) {
        flush_buffer();
        close(g_logger.log_fd);
    }

    // Rotate existing files
    char old_path[280];
    char new_path[280];

    for (int i = g_logger.config.max_files - 1; i >= 0; i--) {
        if (i == 0) {
            snprintf(old_path, sizeof(old_path), "%s", g_logger.config.log_path);
        } else {
            snprintf(old_path, sizeof(old_path), "%s.%d", g_logger.config.log_path, i);
        }

        snprintf(new_path, sizeof(new_path), "%s.%d", g_logger.config.log_path, i + 1);

        if (i == g_logger.config.max_files - 1) {
            unlink(old_path);
        } else {
            rename(old_path, new_path);
        }
    }

    // Open new log file
    g_logger.log_fd = open(g_logger.config.log_path,
                          O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (g_logger.log_fd < 0) {
        return -1;
    }

    g_logger.current_size = 0;
    g_logger.current_file_index++;

    return 0;
}

static int flush_buffer() {
    if (g_logger.buffer_offset > 0 && g_logger.log_fd >= 0) {
        ssize_t written = write(g_logger.log_fd, g_logger.buffer, g_logger.buffer_offset);
        if (written > 0) {
            g_logger.current_size += written;
        }
        g_logger.buffer_offset = 0;
    }
    return 0;
}

static uint64_t get_timestamp_us() {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (uint64_t)ts.tv_sec * 1000000 + ts.tv_nsec / 1000;
}

static const char* get_level_color(LogLevel level) {
    switch (level) {
        case LOG_TRACE: return "\033[90m";   // Gray
        case LOG_DEBUG: return "\033[36m";   // Cyan
        case LOG_INFO:  return "\033[32m";   // Green
        case LOG_WARNING: return "\033[33m"; // Yellow
        case LOG_ERROR: return "\033[31m";   // Red
        case LOG_FATAL: return "\033[35m";   // Magenta
        default: return "\033[0m";
    }
}

static void write_to_console(const char* message, LogLevel level) {
    if (isatty(STDERR_FILENO)) {
        fprintf(stderr, "%s%s\033[0m", get_level_color(level), message);
    } else {
        fprintf(stderr, "%s", message);
    }
}
