// Firmware Update Manager - OTA Update Handler
// Manages firmware downloads, verification, and installation
//
// @benchmark_finding: Command Injection
// @benchmark_severity: Critical
// @benchmark_line: 328

#include <cstdlib>
#include <cstring>
#include <cstdio>
#include <unistd.h>
#include <sys/stat.h>
#include <dirent.h>
#include <fcntl.h>
#include <errno.h>

#define UPDATE_DIR "/var/firmware"
#define TEMP_DIR "/tmp/fw_update"
#define MAX_FILENAME_LEN 256
#define MAX_PATH_LEN 512
#define CHUNK_SIZE 65536
#define MAX_FIRMWARE_SIZE (64 * 1024 * 1024)

// Update states
enum UpdateState {
    UPDATE_IDLE = 0,
    UPDATE_DOWNLOADING,
    UPDATE_VERIFYING,
    UPDATE_INSTALLING,
    UPDATE_COMPLETE,
    UPDATE_FAILED
};

// Firmware metadata
struct FirmwareInfo {
    char version[32];
    char filename[MAX_FILENAME_LEN];
    uint32_t size;
    uint32_t checksum;
    uint64_t timestamp;
    bool verified;
};

// Update context
struct UpdateContext {
    UpdateState state;
    FirmwareInfo current;
    FirmwareInfo pending;
    uint32_t bytes_downloaded;
    uint32_t bytes_written;
    int download_fd;
    char error_message[256];
};

// Global update context
static UpdateContext g_update_ctx;
static bool g_initialized = false;

// Forward declarations
static int ensure_directory(const char* path);
static uint32_t calculate_crc32(const void* data, size_t len);
static int verify_signature(const char* filepath);
static void log_update(const char* format, ...);
static int safe_copy_file(const char* src, const char* dst);

// Initialize the update manager
int update_manager_init() {
    if (g_initialized) {
        return 0;
    }

    memset(&g_update_ctx, 0, sizeof(g_update_ctx));
    g_update_ctx.state = UPDATE_IDLE;
    g_update_ctx.download_fd = -1;

    // Ensure directories exist
    if (ensure_directory(UPDATE_DIR) < 0) {
        log_update("Failed to create update directory");
        return -1;
    }

    if (ensure_directory(TEMP_DIR) < 0) {
        log_update("Failed to create temp directory");
        return -1;
    }

    g_initialized = true;
    log_update("Update manager initialized");

    return 0;
}

// Shutdown the update manager
void update_manager_shutdown() {
    if (!g_initialized) {
        return;
    }

    if (g_update_ctx.download_fd >= 0) {
        close(g_update_ctx.download_fd);
        g_update_ctx.download_fd = -1;
    }

    g_update_ctx.state = UPDATE_IDLE;
    g_initialized = false;

    log_update("Update manager shutdown");
}

// Get current firmware version
const char* update_manager_get_version() {
    return g_update_ctx.current.version;
}

// Get update state
UpdateState update_manager_get_state() {
    return g_update_ctx.state;
}

// Get download progress (0-100)
int update_manager_get_progress() {
    if (g_update_ctx.pending.size == 0) {
        return 0;
    }
    return (g_update_ctx.bytes_downloaded * 100) / g_update_ctx.pending.size;
}

// Start firmware download
int update_manager_start_download(const char* url, const char* version) {
    if (!g_initialized) {
        return -1;
    }

    if (g_update_ctx.state != UPDATE_IDLE) {
        log_update("Update already in progress");
        return -1;
    }

    // Setup pending firmware info
    strncpy(g_update_ctx.pending.version, version, sizeof(g_update_ctx.pending.version) - 1);

    // Create temp file for download
    char temp_path[MAX_PATH_LEN];
    snprintf(temp_path, sizeof(temp_path), "%s/firmware_%s.bin", TEMP_DIR, version);

    g_update_ctx.download_fd = open(temp_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (g_update_ctx.download_fd < 0) {
        log_update("Failed to create temp file: %s", strerror(errno));
        return -1;
    }

    strncpy(g_update_ctx.pending.filename, temp_path, MAX_FILENAME_LEN - 1);
    g_update_ctx.bytes_downloaded = 0;
    g_update_ctx.state = UPDATE_DOWNLOADING;

    log_update("Starting download from %s", url);
    return 0;
}

// Write downloaded chunk
int update_manager_write_chunk(const void* data, size_t len) {
    if (g_update_ctx.state != UPDATE_DOWNLOADING) {
        return -1;
    }

    if (g_update_ctx.download_fd < 0) {
        return -1;
    }

    ssize_t written = write(g_update_ctx.download_fd, data, len);
    if (written < 0) {
        log_update("Write failed: %s", strerror(errno));
        g_update_ctx.state = UPDATE_FAILED;
        return -1;
    }

    g_update_ctx.bytes_downloaded += written;

    // Check size limit
    if (g_update_ctx.bytes_downloaded > MAX_FIRMWARE_SIZE) {
        log_update("Firmware exceeds maximum size");
        g_update_ctx.state = UPDATE_FAILED;
        return -1;
    }

    return written;
}

// Complete download and start verification
int update_manager_finish_download() {
    if (g_update_ctx.state != UPDATE_DOWNLOADING) {
        return -1;
    }

    if (g_update_ctx.download_fd >= 0) {
        close(g_update_ctx.download_fd);
        g_update_ctx.download_fd = -1;
    }

    g_update_ctx.pending.size = g_update_ctx.bytes_downloaded;
    g_update_ctx.state = UPDATE_VERIFYING;

    log_update("Download complete, %u bytes", g_update_ctx.bytes_downloaded);

    // Verify the firmware
    if (verify_signature(g_update_ctx.pending.filename) < 0) {
        log_update("Signature verification failed");
        g_update_ctx.state = UPDATE_FAILED;
        return -1;
    }

    g_update_ctx.pending.verified = true;
    log_update("Firmware verified successfully");

    return 0;
}

// Install the verified firmware
int update_manager_install() {
    if (g_update_ctx.state != UPDATE_VERIFYING || !g_update_ctx.pending.verified) {
        return -1;
    }

    g_update_ctx.state = UPDATE_INSTALLING;

    // Create final destination path
    char dest_path[MAX_PATH_LEN];
    snprintf(dest_path, sizeof(dest_path), "%s/firmware_%s.bin",
             UPDATE_DIR, g_update_ctx.pending.version);

    // Copy firmware to final location
    if (safe_copy_file(g_update_ctx.pending.filename, dest_path) < 0) {
        log_update("Failed to install firmware");
        g_update_ctx.state = UPDATE_FAILED;
        return -1;
    }

    // Remove temp file
    unlink(g_update_ctx.pending.filename);

    // Update current version
    memcpy(&g_update_ctx.current, &g_update_ctx.pending, sizeof(FirmwareInfo));
    g_update_ctx.state = UPDATE_COMPLETE;

    log_update("Firmware %s installed successfully", g_update_ctx.current.version);

    return 0;
}

// Cancel current update
void update_manager_cancel() {
    if (g_update_ctx.download_fd >= 0) {
        close(g_update_ctx.download_fd);
        g_update_ctx.download_fd = -1;
    }

    // Remove temp file
    if (g_update_ctx.pending.filename[0] != '\0') {
        unlink(g_update_ctx.pending.filename);
    }

    memset(&g_update_ctx.pending, 0, sizeof(FirmwareInfo));
    g_update_ctx.state = UPDATE_IDLE;

    log_update("Update cancelled");
}

// Get error message
const char* update_manager_get_error() {
    return g_update_ctx.error_message;
}

// List available firmware versions
int update_manager_list_versions(char** versions, int max_versions) {
    DIR* dir = opendir(UPDATE_DIR);
    if (!dir) {
        return -1;
    }

    int count = 0;
    struct dirent* entry;

    while ((entry = readdir(dir)) != NULL && count < max_versions) {
        if (entry->d_type != DT_REG) {
            continue;
        }

        // Check if it's a firmware file
        if (strstr(entry->d_name, "firmware_") == entry->d_name &&
            strstr(entry->d_name, ".bin") != NULL) {

            // Extract version from filename
            char* version_start = entry->d_name + 9;  // Skip "firmware_"
            char* version_end = strstr(version_start, ".bin");

            if (version_end && versions[count]) {
                int len = version_end - version_start;
                strncpy(versions[count], version_start, len);
                versions[count][len] = '\0';
                count++;
            }
        }
    }

    closedir(dir);
    return count;
}

// Delete old firmware versions
int update_manager_cleanup(int keep_count) {
    // Would implement version cleanup logic here
    log_update("Cleanup requested, keeping %d versions", keep_count);
    return 0;
}

// Execute pre/post update hooks
int update_manager_run_hook(const char* hook_name) {
    if (!g_initialized) {
        return -1;
    }

    // Build hook script path
    char hook_path[MAX_PATH_LEN];
    snprintf(hook_path, sizeof(hook_path), "/etc/firmware/hooks/%s", hook_name);

    // Check if hook exists
    struct stat st;
    if (stat(hook_path, &st) < 0) {
        log_update("Hook not found: %s", hook_path);
        return 0;  // Not an error if hook doesn't exist
    }

    // VULNERABILITY: Command injection via hook_name
    // User-controlled hook_name is passed directly to system()
    char command[512];
    sprintf(command, "/bin/sh %s", hook_path);
    int result = system(command);

    if (result != 0) {
        log_update("Hook %s failed with code %d", hook_name, result);
        return -1;
    }

    log_update("Hook %s executed successfully", hook_name);
    return 0;
}

// Helper functions

static int ensure_directory(const char* path) {
    struct stat st;

    if (stat(path, &st) == 0) {
        if (S_ISDIR(st.st_mode)) {
            return 0;
        }
        return -1;
    }

    if (mkdir(path, 0755) < 0) {
        return -1;
    }

    return 0;
}

static uint32_t calculate_crc32(const void* data, size_t len) {
    const uint8_t* bytes = (const uint8_t*)data;
    uint32_t crc = 0xFFFFFFFF;

    for (size_t i = 0; i < len; i++) {
        crc ^= bytes[i];
        for (int j = 0; j < 8; j++) {
            crc = (crc >> 1) ^ (0xEDB88320 & -(crc & 1));
        }
    }

    return ~crc;
}

static int verify_signature(const char* filepath) {
    // Read file and verify signature
    int fd = open(filepath, O_RDONLY);
    if (fd < 0) {
        return -1;
    }

    // Get file size
    struct stat st;
    if (fstat(fd, &st) < 0) {
        close(fd);
        return -1;
    }

    // Allocate buffer
    uint8_t* buffer = (uint8_t*)malloc(st.st_size);
    if (!buffer) {
        close(fd);
        return -1;
    }

    // Read file
    ssize_t bytes_read = read(fd, buffer, st.st_size);
    close(fd);

    if (bytes_read != st.st_size) {
        free(buffer);
        return -1;
    }

    // Calculate and verify checksum (simplified)
    uint32_t checksum = calculate_crc32(buffer, st.st_size);
    free(buffer);

    // In real implementation, would verify against manifest
    g_update_ctx.pending.checksum = checksum;

    return 0;
}

static int safe_copy_file(const char* src, const char* dst) {
    int src_fd = open(src, O_RDONLY);
    if (src_fd < 0) {
        return -1;
    }

    int dst_fd = open(dst, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (dst_fd < 0) {
        close(src_fd);
        return -1;
    }

    uint8_t buffer[CHUNK_SIZE];
    ssize_t bytes_read;

    while ((bytes_read = read(src_fd, buffer, sizeof(buffer))) > 0) {
        ssize_t written = write(dst_fd, buffer, bytes_read);
        if (written != bytes_read) {
            close(src_fd);
            close(dst_fd);
            return -1;
        }
    }

    close(src_fd);
    close(dst_fd);

    return bytes_read < 0 ? -1 : 0;
}

static void log_update(const char* format, ...) {
    va_list args;
    va_start(args, format);

    char buffer[512];
    vsnprintf(buffer, sizeof(buffer), format, args);

    fprintf(stderr, "[UPDATE] %s\n", buffer);

    va_end(args);
}
