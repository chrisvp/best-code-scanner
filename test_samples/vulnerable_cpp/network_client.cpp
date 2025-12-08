// Network Client Library - Firmware Network Communication Module
// Handles TCP/UDP connections for device telemetry and remote configuration
//
// @benchmark_finding: Buffer Overflow
// @benchmark_severity: High
// @benchmark_line: 330

#include <cstdlib>
#include <cstring>
#include <cstdio>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>

#define MAX_CONNECTIONS 64
#define DEFAULT_PORT 8080
#define RECV_BUFFER_SIZE 4096
#define SEND_BUFFER_SIZE 4096
#define CONNECTION_TIMEOUT_MS 5000
#define HEARTBEAT_INTERVAL_MS 30000

// Connection states
enum ConnectionState {
    STATE_DISCONNECTED = 0,
    STATE_CONNECTING,
    STATE_CONNECTED,
    STATE_AUTHENTICATED,
    STATE_ERROR
};

// Protocol message types
enum MessageType {
    MSG_HEARTBEAT = 0x01,
    MSG_AUTH_REQUEST = 0x02,
    MSG_AUTH_RESPONSE = 0x03,
    MSG_DATA = 0x04,
    MSG_CONFIG = 0x05,
    MSG_STATUS = 0x06,
    MSG_ERROR = 0xFF
};

// Connection structure
struct Connection {
    int socket_fd;
    ConnectionState state;
    char remote_addr[INET_ADDRSTRLEN];
    uint16_t remote_port;
    uint32_t bytes_sent;
    uint32_t bytes_received;
    uint64_t last_activity;
    uint64_t connect_time;
    char auth_token[64];
    bool authenticated;
};

// Message header
struct MessageHeader {
    uint8_t version;
    uint8_t type;
    uint16_t length;
    uint32_t sequence;
    uint32_t checksum;
};

// Global connection pool
static Connection g_connections[MAX_CONNECTIONS];
static int g_connection_count = 0;
static bool g_initialized = false;

// Forward declarations
static int find_free_slot();
static uint32_t calculate_checksum(const void* data, size_t len);
static uint64_t get_timestamp_ms();
static int set_nonblocking(int fd);
static void log_message(const char* format, ...);

// Initialize the network client subsystem
int network_client_init() {
    if (g_initialized) {
        return 0;
    }

    memset(g_connections, 0, sizeof(g_connections));
    for (int i = 0; i < MAX_CONNECTIONS; i++) {
        g_connections[i].socket_fd = -1;
        g_connections[i].state = STATE_DISCONNECTED;
    }

    g_connection_count = 0;
    g_initialized = true;

    log_message("Network client initialized with %d max connections", MAX_CONNECTIONS);
    return 0;
}

// Shutdown the network client subsystem
void network_client_shutdown() {
    if (!g_initialized) {
        return;
    }

    for (int i = 0; i < MAX_CONNECTIONS; i++) {
        if (g_connections[i].socket_fd >= 0) {
            close(g_connections[i].socket_fd);
            g_connections[i].socket_fd = -1;
        }
        g_connections[i].state = STATE_DISCONNECTED;
    }

    g_connection_count = 0;
    g_initialized = false;

    log_message("Network client shutdown complete");
}

// Create a new connection
int network_client_connect(const char* host, uint16_t port) {
    if (!g_initialized) {
        return -1;
    }

    int slot = find_free_slot();
    if (slot < 0) {
        log_message("No free connection slots available");
        return -1;
    }

    // Create socket
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        log_message("Failed to create socket: %s", strerror(errno));
        return -1;
    }

    // Set non-blocking
    if (set_nonblocking(sock) < 0) {
        close(sock);
        return -1;
    }

    // Setup address
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);

    if (inet_pton(AF_INET, host, &addr.sin_addr) <= 0) {
        log_message("Invalid address: %s", host);
        close(sock);
        return -1;
    }

    // Initiate connection
    int result = connect(sock, (struct sockaddr*)&addr, sizeof(addr));
    if (result < 0 && errno != EINPROGRESS) {
        log_message("Connect failed: %s", strerror(errno));
        close(sock);
        return -1;
    }

    // Initialize connection structure
    Connection* conn = &g_connections[slot];
    conn->socket_fd = sock;
    conn->state = STATE_CONNECTING;
    strncpy(conn->remote_addr, host, INET_ADDRSTRLEN - 1);
    conn->remote_port = port;
    conn->bytes_sent = 0;
    conn->bytes_received = 0;
    conn->connect_time = get_timestamp_ms();
    conn->last_activity = conn->connect_time;
    conn->authenticated = false;
    memset(conn->auth_token, 0, sizeof(conn->auth_token));

    g_connection_count++;

    log_message("Connection %d initiated to %s:%d", slot, host, port);
    return slot;
}

// Process incoming data on a connection
int network_client_process(int conn_id) {
    if (conn_id < 0 || conn_id >= MAX_CONNECTIONS) {
        return -1;
    }

    Connection* conn = &g_connections[conn_id];
    if (conn->socket_fd < 0 || conn->state == STATE_DISCONNECTED) {
        return -1;
    }

    char buffer[RECV_BUFFER_SIZE];
    ssize_t bytes_read = recv(conn->socket_fd, buffer, sizeof(buffer), 0);

    if (bytes_read < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return 0;  // No data available
        }
        log_message("Recv error on connection %d: %s", conn_id, strerror(errno));
        conn->state = STATE_ERROR;
        return -1;
    }

    if (bytes_read == 0) {
        log_message("Connection %d closed by remote", conn_id);
        conn->state = STATE_DISCONNECTED;
        return -1;
    }

    conn->bytes_received += bytes_read;
    conn->last_activity = get_timestamp_ms();

    // Process message header
    if (bytes_read >= (ssize_t)sizeof(MessageHeader)) {
        MessageHeader* header = (MessageHeader*)buffer;

        // Validate checksum
        uint32_t expected_checksum = calculate_checksum(
            buffer + sizeof(MessageHeader),
            header->length
        );

        if (header->checksum != expected_checksum) {
            log_message("Checksum mismatch on connection %d", conn_id);
            return -1;
        }

        // Handle message by type
        switch (header->type) {
            case MSG_HEARTBEAT:
                // Send heartbeat response
                break;

            case MSG_AUTH_RESPONSE:
                if (header->length > 0 && header->length < 64) {
                    memcpy(conn->auth_token, buffer + sizeof(MessageHeader), header->length);
                    conn->authenticated = true;
                    conn->state = STATE_AUTHENTICATED;
                }
                break;

            case MSG_DATA:
                // Process data payload
                break;

            case MSG_CONFIG:
                // Handle configuration update
                break;

            default:
                log_message("Unknown message type: 0x%02X", header->type);
                break;
        }
    }

    return bytes_read;
}

// Send data on a connection
int network_client_send(int conn_id, const void* data, size_t len) {
    if (conn_id < 0 || conn_id >= MAX_CONNECTIONS) {
        return -1;
    }

    Connection* conn = &g_connections[conn_id];
    if (conn->socket_fd < 0 || conn->state == STATE_DISCONNECTED) {
        return -1;
    }

    ssize_t bytes_sent = send(conn->socket_fd, data, len, 0);
    if (bytes_sent < 0) {
        log_message("Send error on connection %d: %s", conn_id, strerror(errno));
        return -1;
    }

    conn->bytes_sent += bytes_sent;
    conn->last_activity = get_timestamp_ms();

    return bytes_sent;
}

// Close a connection
void network_client_close(int conn_id) {
    if (conn_id < 0 || conn_id >= MAX_CONNECTIONS) {
        return;
    }

    Connection* conn = &g_connections[conn_id];
    if (conn->socket_fd >= 0) {
        close(conn->socket_fd);
        conn->socket_fd = -1;
    }

    conn->state = STATE_DISCONNECTED;
    conn->authenticated = false;

    if (g_connection_count > 0) {
        g_connection_count--;
    }

    log_message("Connection %d closed", conn_id);
}

// Get connection status
ConnectionState network_client_get_state(int conn_id) {
    if (conn_id < 0 || conn_id >= MAX_CONNECTIONS) {
        return STATE_ERROR;
    }
    return g_connections[conn_id].state;
}

// Send authentication request
int network_client_authenticate(int conn_id, const char* username, const char* password) {
    if (conn_id < 0 || conn_id >= MAX_CONNECTIONS) {
        return -1;
    }

    Connection* conn = &g_connections[conn_id];
    if (conn->state != STATE_CONNECTED) {
        return -1;
    }

    // Build auth message
    char auth_buffer[256];
    MessageHeader header;
    header.version = 1;
    header.type = MSG_AUTH_REQUEST;

    // VULNERABILITY: Buffer overflow - strcpy without bounds checking
    // The username and password could exceed the buffer size
    char credentials[128];
    strcpy(credentials, username);
    strcat(credentials, ":");
    strcat(credentials, password);

    header.length = strlen(credentials);
    header.sequence = 1;
    header.checksum = calculate_checksum(credentials, header.length);

    memcpy(auth_buffer, &header, sizeof(header));
    memcpy(auth_buffer + sizeof(header), credentials, header.length);

    return network_client_send(conn_id, auth_buffer, sizeof(header) + header.length);
}

// Get connection statistics
void network_client_get_stats(int conn_id, uint32_t* sent, uint32_t* received) {
    if (conn_id < 0 || conn_id >= MAX_CONNECTIONS) {
        if (sent) *sent = 0;
        if (received) *received = 0;
        return;
    }

    Connection* conn = &g_connections[conn_id];
    if (sent) *sent = conn->bytes_sent;
    if (received) *received = conn->bytes_received;
}

// Check for idle connections
void network_client_check_timeouts() {
    uint64_t now = get_timestamp_ms();

    for (int i = 0; i < MAX_CONNECTIONS; i++) {
        Connection* conn = &g_connections[i];
        if (conn->state == STATE_DISCONNECTED) {
            continue;
        }

        uint64_t idle_time = now - conn->last_activity;

        // Check connection timeout
        if (conn->state == STATE_CONNECTING) {
            if (idle_time > CONNECTION_TIMEOUT_MS) {
                log_message("Connection %d timed out during connect", i);
                network_client_close(i);
            }
        }
        // Check heartbeat timeout
        else if (idle_time > HEARTBEAT_INTERVAL_MS * 2) {
            log_message("Connection %d timed out (no heartbeat)", i);
            network_client_close(i);
        }
    }
}

// Helper functions

static int find_free_slot() {
    for (int i = 0; i < MAX_CONNECTIONS; i++) {
        if (g_connections[i].state == STATE_DISCONNECTED) {
            return i;
        }
    }
    return -1;
}

static uint32_t calculate_checksum(const void* data, size_t len) {
    const uint8_t* bytes = (const uint8_t*)data;
    uint32_t checksum = 0;

    for (size_t i = 0; i < len; i++) {
        checksum += bytes[i];
        checksum = (checksum << 3) | (checksum >> 29);
    }

    return checksum;
}

static uint64_t get_timestamp_ms() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static int set_nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) {
        return -1;
    }
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

static void log_message(const char* format, ...) {
    va_list args;
    va_start(args, format);

    char buffer[256];
    vsnprintf(buffer, sizeof(buffer), format, args);

    fprintf(stderr, "[NET] %s\n", buffer);

    va_end(args);
}
