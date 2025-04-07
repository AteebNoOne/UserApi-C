#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ctype.h>

#define MAX_USERS 100
#define MAX_BUFFER_SIZE 4096
#define SERVER_PORT 8080

// User data structure
typedef struct {
    int id;
    char username[50];
    char email[100];
    char password[50]; // Note: In a real app, store password hashes, not plaintext
    bool active;
} User;

// Database simulation
typedef struct {
    User users[MAX_USERS];
    int count;
    int next_id;
} UserDB;

// Global database instance
UserDB user_db;

// Initialize database
void init_db() {
    user_db.count = 0;
    user_db.next_id = 1;
    
    // Add some sample users
    User user1 = {1, "john_doe", "john@example.com", "pass123", true};
    User user2 = {2, "jane_smith", "jane@example.com", "pass456", true};
    
    user_db.users[0] = user1;
    user_db.users[1] = user2;
    user_db.count = 2;
    user_db.next_id = 3;
}

// CRUD Operations

// Create a new user and return the new user's ID or -1 on failure
int create_user(const char* username, const char* email, const char* password) {
    if (user_db.count >= MAX_USERS) {
        return -1;  // Database full
    }
    
    // Check if username already exists
    for (int i = 0; i < user_db.count; i++) {
        if (strcmp(user_db.users[i].username, username) == 0) {
            return -1;  // Username already exists
        }
    }
    
    User new_user;
    new_user.id = user_db.next_id++;
    strncpy(new_user.username, username, sizeof(new_user.username) - 1);
    strncpy(new_user.email, email, sizeof(new_user.email) - 1);
    strncpy(new_user.password, password, sizeof(new_user.password) - 1);
    new_user.active = true;
    
    user_db.users[user_db.count] = new_user;
    user_db.count++;
    
    return new_user.id;
}

// Get user by ID (returns NULL if not found)
User* get_user_by_id(int id) {
    for (int i = 0; i < user_db.count; i++) {
        if (user_db.users[i].id == id) {
            return &user_db.users[i];
        }
    }
    return NULL;
}

// Update user by ID (returns true on success)
bool update_user(int id, const char* username, const char* email, const char* password) {
    for (int i = 0; i < user_db.count; i++) {
        if (user_db.users[i].id == id) {
            if (username != NULL && strlen(username) > 0) {
                strncpy(user_db.users[i].username, username, sizeof(user_db.users[i].username) - 1);
            }
            if (email != NULL && strlen(email) > 0) {
                strncpy(user_db.users[i].email, email, sizeof(user_db.users[i].email) - 1);
            }
            if (password != NULL && strlen(password) > 0) {
                strncpy(user_db.users[i].password, password, sizeof(user_db.users[i].password) - 1);
            }
            return true;
        }
    }
    return false;
}

// Delete user by ID (returns true on success)
bool delete_user(int id) {
    for (int i = 0; i < user_db.count; i++) {
        if (user_db.users[i].id == id) {
            // Move all elements after this one back by one position
            for (int j = i; j < user_db.count - 1; j++) {
                user_db.users[j] = user_db.users[j + 1];
            }
            user_db.count--;
            return true;
        }
    }
    return false;
}

// List all users (returns JSON string, caller must free)
char* list_all_users() {
    char* result = (char*)malloc(MAX_BUFFER_SIZE);
    if (!result) return NULL;
    
    strcpy(result, "{\n  \"users\": [\n");
    
    for (int i = 0; i < user_db.count; i++) {
        char user_json[512];
        sprintf(user_json, "    {\n      \"id\": %d,\n      \"username\": \"%s\",\n"
                "      \"email\": \"%s\",\n      \"active\": %s\n    }",
                user_db.users[i].id, user_db.users[i].username, 
                user_db.users[i].email, user_db.users[i].active ? "true" : "false");
        
        strcat(result, user_json);
        if (i < user_db.count - 1) {
            strcat(result, ",\n");
        } else {
            strcat(result, "\n");
        }
    }
    
    strcat(result, "  ]\n}");
    return result;
}

// Convert user to JSON string (caller must free)
char* user_to_json(User* user) {
    if (!user) return NULL;
    
    char* result = (char*)malloc(512);
    if (!result) return NULL;
    
    sprintf(result, "{\n  \"id\": %d,\n  \"username\": \"%s\",\n"
            "  \"email\": \"%s\",\n  \"active\": %s\n}",
            user->id, user->username, user->email, 
            user->active ? "true" : "false");
    
    return result;
}

// Parse JSON request to extract fields (very basic implementation)
bool parse_json_field(const char* json, const char* field_name, char* output, size_t output_size) {
    char search_pattern[50];
    sprintf(search_pattern, "\"%s\":", field_name);
    
    char* field_start = strstr(json, search_pattern);
    if (!field_start) return false;
    
    field_start += strlen(search_pattern);
    
    // Skip whitespace
    while (isspace(*field_start)) field_start++;
    
    if (*field_start == '"') {
        // String value
        field_start++;
        char* field_end = strchr(field_start, '"');
        if (!field_end) return false;
        
        size_t length = field_end - field_start;
        if (length >= output_size) length = output_size - 1;
        
        strncpy(output, field_start, length);
        output[length] = '\0';
        return true;
    } else if (isdigit(*field_start) || *field_start == '-') {
        // Numeric value
        char* field_end = field_start;
        while (isdigit(*field_end) || *field_end == '.' || *field_end == '-') field_end++;
        
        size_t length = field_end - field_start;
        if (length >= output_size) length = output_size - 1;
        
        strncpy(output, field_start, length);
        output[length] = '\0';
        return true;
    }
    
    return false;
}

// HTTP Server and Request Handling

// Parse HTTP request to extract method, path, and body
void parse_http_request(const char* request, char* method, char* path, char* body) {
    // Extract method (GET, POST, PUT, DELETE)
    sscanf(request, "%s", method);
    
    // Extract path
    sscanf(request, "%*s %s", path);
    
    // Extract body (after blank line)
    const char* body_start = strstr(request, "\r\n\r\n");
    if (body_start) {
        strcpy(body, body_start + 4);
    } else {
        body[0] = '\0';
    }
}

// Extract user ID from path (/users/123 -> 123)
int extract_id_from_path(const char* path) {
    if (strncmp(path, "/users/", 7) == 0) {
        return atoi(path + 7);
    }
    return -1;
}

// Build HTTP response
void build_response(char* response, int status_code, const char* content_type, const char* body) {
    const char* status_text = "";
    
    switch (status_code) {
        case 200: status_text = "OK"; break;
        case 201: status_text = "Created"; break;
        case 204: status_text = "No Content"; break;
        case 400: status_text = "Bad Request"; break;
        case 404: status_text = "Not Found"; break;
        case 500: status_text = "Internal Server Error"; break;
        default: status_text = "Unknown"; break;
    }
    
    sprintf(response, 
            "HTTP/1.1 %d %s\r\n"
            "Content-Type: %s\r\n"
            "Content-Length: %lu\r\n"
            "Connection: close\r\n"
            "\r\n"
            "%s",
            status_code, status_text, content_type, 
            body ? strlen(body) : 0, body ? body : "");
}

// Process request and generate response
void process_request(const char* request, char* response) {
    char method[10], path[100], body[MAX_BUFFER_SIZE];
    parse_http_request(request, method, path, body);
    
    printf("Received %s request for %s\n", method, path);
    
    // Handle CRUD operations based on method and path
    if (strcmp(path, "/users") == 0 && strcmp(method, "GET") == 0) {
        // LIST users
        char* users_json = list_all_users();
        if (users_json) {
            build_response(response, 200, "application/json", users_json);
            free(users_json);
        } else {
            build_response(response, 500, "application/json", "{\"error\":\"Failed to generate user list\"}");
        }
    } 
    else if (strcmp(path, "/users") == 0 && strcmp(method, "POST") == 0) {
        // CREATE user
        char username[50] = {0}, email[100] = {0}, password[50] = {0};
        parse_json_field(body, "username", username, sizeof(username));
        parse_json_field(body, "email", email, sizeof(email));
        parse_json_field(body, "password", password, sizeof(password));
        
        if (strlen(username) > 0 && strlen(email) > 0 && strlen(password) > 0) {
            int new_id = create_user(username, email, password);
            if (new_id > 0) {
                User* new_user = get_user_by_id(new_id);
                char* user_json = user_to_json(new_user);
                build_response(response, 201, "application/json", user_json);
                free(user_json);
            } else {
                build_response(response, 400, "application/json", 
                              "{\"error\":\"Failed to create user. Username may already exist.\"}");
            }
        } else {
            build_response(response, 400, "application/json", 
                          "{\"error\":\"Missing required fields\"}");
        }
    }
    else if (strncmp(path, "/users/", 7) == 0 && strcmp(method, "GET") == 0) {
        // READ user by ID
        int user_id = extract_id_from_path(path);
        if (user_id > 0) {
            User* user = get_user_by_id(user_id);
            if (user) {
                char* user_json = user_to_json(user);
                build_response(response, 200, "application/json", user_json);
                free(user_json);
            } else {
                build_response(response, 404, "application/json", 
                              "{\"error\":\"User not found\"}");
            }
        } else {
            build_response(response, 400, "application/json", 
                          "{\"error\":\"Invalid user ID\"}");
        }
    }
    else if (strncmp(path, "/users/", 7) == 0 && strcmp(method, "PUT") == 0) {
        // UPDATE user
        int user_id = extract_id_from_path(path);
        if (user_id > 0) {
            char username[50] = {0}, email[100] = {0}, password[50] = {0};
            parse_json_field(body, "username", username, sizeof(username));
            parse_json_field(body, "email", email, sizeof(email));
            parse_json_field(body, "password", password, sizeof(password));
            
            if (update_user(user_id, username, email, password)) {
                User* updated_user = get_user_by_id(user_id);
                char* user_json = user_to_json(updated_user);
                build_response(response, 200, "application/json", user_json);
                free(user_json);
            } else {
                build_response(response, 404, "application/json", 
                              "{\"error\":\"User not found\"}");
            }
        } else {
            build_response(response, 400, "application/json", 
                          "{\"error\":\"Invalid user ID\"}");
        }
    }
    else if (strncmp(path, "/users/", 7) == 0 && strcmp(method, "DELETE") == 0) {
        // DELETE user
        int user_id = extract_id_from_path(path);
        if (user_id > 0) {
            if (delete_user(user_id)) {
                build_response(response, 204, "application/json", "");
            } else {
                build_response(response, 404, "application/json", 
                              "{\"error\":\"User not found\"}");
            }
        } else {
            build_response(response, 400, "application/json", 
                          "{\"error\":\"Invalid user ID\"}");
        }
    }
    else {
        // Unknown path or method
        build_response(response, 404, "application/json", 
                      "{\"error\":\"Path not found\"}");
    }
}

// Main function to run the HTTP server
int main() {
    // Initialize user database
    init_db();
    
    // Create socket
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }
    
    // Set socket options for reuse
    int opt = 1;
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        perror("Setsockopt failed");
        exit(EXIT_FAILURE);
    }
    
    // Configure server address
    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(SERVER_PORT);
    
    // Bind socket
    if (bind(server_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Bind failed");
        exit(EXIT_FAILURE);
    }
    
    // Listen for connections
    if (listen(server_fd, 5) < 0) {
        perror("Listen failed");
        exit(EXIT_FAILURE);
    }
    
    printf("Server listening on port %d...\n", SERVER_PORT);
    
    // Accept connections and handle requests
    while (1) {
        struct sockaddr_in client_addr;
        socklen_t client_addr_len = sizeof(client_addr);
        
        int client_fd = accept(server_fd, (struct sockaddr *)&client_addr, &client_addr_len);
        if (client_fd < 0) {
            perror("Accept failed");
            continue;
        }
        
        char client_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(client_addr.sin_addr), client_ip, INET_ADDRSTRLEN);
        printf("Client connected: %s\n", client_ip);
        
        // Receive HTTP request
        char request_buffer[MAX_BUFFER_SIZE] = {0};
        ssize_t bytes_received = recv(client_fd, request_buffer, MAX_BUFFER_SIZE - 1, 0);
        
        if (bytes_received > 0) {
            // Process request and build response
            char response_buffer[MAX_BUFFER_SIZE];
            process_request(request_buffer, response_buffer);
            
            // Send response
            send(client_fd, response_buffer, strlen(response_buffer), 0);
        }
        
        // Close client connection
        close(client_fd);
        printf("Client disconnected\n");
    }
    
    // Close server socket
    close(server_fd);
    
    return 0;
}