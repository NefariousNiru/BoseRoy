#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <ctype.h>
#include <netinet/in.h>

#define PORT 9999
#define BUFFER_SIZE 1024
#define MAX_DENYLIST_SIZE 2048
#define MAX_DOMAIN_LENGTH 255
char denylist[MAX_DENYLIST_SIZE][MAX_DOMAIN_LENGTH];
int denylist_count = 0;
char upstream_domain[] = "8.8.8.8";

void load_denylist(const char *filename) {
    FILE *file = fopen(filename, "r");
    if (!file) {
        perror("Failed to open denylist file");
        return;
    }

    while (fgets(denylist[denylist_count], MAX_DOMAIN_LENGTH, file)) {
        denylist[denylist_count][strcspn(denylist[denylist_count], "\n")] = '\0';
        denylist_count++;

        if (denylist_count >= MAX_DENYLIST_SIZE) {
            printf("Deny List is full\n");
            break;
        }
    }
    fclose(file);
}

int is_domain_blocked(const char *domain) {
    for(int i = 0; i < denylist_count; i++) {
        if(strcmp(denylist[i], domain) == 0){
            return 1;
        }
    }
    return 0;
}

void send_nxdomain_response(int sock, struct sockaddr_in *client_addr, socklen_t addr_len, char *buffer, int length) {
    buffer[2] |= 0x80;  // Set QR bit to 1 (response)
    buffer[3] |= 0x03;  // Set RCODE to 3 (NXDOMAIN)

    sendto(sock, buffer, length, 0, (struct sockaddr *)client_addr, addr_len);
}

void forward_dns_query(int sock, char *buffer, int length, struct sockaddr_in *client_addr, socklen_t addr_len) {
    int resolver_sock;
    struct sockaddr_in resolver_addr;

    resolver_addr.sin_family = AF_INET;
    resolver_addr.sin_port = htons(53);
    inet_pton(AF_INET, upstream_domain, &resolver_addr.sin_addr);

    if ((resolver_sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("Resolver socket creation failed");
        return;
    }

    sendto(resolver_sock, buffer, length, 0, (struct sockaddr *)&resolver_addr, sizeof(resolver_addr));

    // Receive the resolver's response
    int n = recvfrom(resolver_sock, buffer, BUFFER_SIZE, 0, NULL, NULL);
    if (n < 0) {
        perror("Error receiving response from resolver");
        close(resolver_sock);
        return;
    }

    // Send the resolver's response back to the client
    sendto(sock, buffer, n, 0, (struct sockaddr *)client_addr, addr_len);

    // Close the resolver socket
    close(resolver_sock);
}

int create_UDP_socket(){
    int sockfd;
    if((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("UDP Socket Creation Failed");
        exit(EXIT_FAILURE);
    }
    return sockfd;
}

struct sockaddr_in define_server_address() {
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    
    server_addr.sin_family = AF_INET;             // IPv4
    server_addr.sin_addr.s_addr = INADDR_ANY;     // Listen on any available IP address
    server_addr.sin_port = htons(PORT);           // Convert port to network byte order
    
    return server_addr;                           // Return the configured server address
}

int bind_server(int sockfd, struct sockaddr_in server_addr) {
    if (bind(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Bind Failed");
        return -1;
    }
    return 0;
}

void parse_dns_query(char *buffer, int length, char *domain) {
    int header_size = 12;

    if (length < header_size) {
        printf("Invalid Length DNS Message\n");
        domain[0] = '\0'; 
        return;
    }

    char *qname = buffer + header_size;
    char *end_msg = buffer + length;
    char *domain_ptr = domain; 

    while (qname < end_msg && *qname != 0) {
        int label_len = *qname;
        if (label_len < 0 || qname + label_len >= end_msg) {
            printf("\nError: Label length exceeds message bounds or is invalid\n");
            domain[0] = '\0'; 
            return;
        }
        qname++;  

        for (int i = 0; i < label_len; i++) {
            if (qname >= end_msg || (!isalnum(*qname) && *qname != '-')) {
                printf("\nError: Unexpected character in domain name\n");
                domain[0] = '\0';
                return;
            }
            *domain_ptr++ = *qname++;
        }

        if (*qname != 0) {
            *domain_ptr++ = '.';
        }
    }

    *domain_ptr = '\0';
    printf("Requested Domain: %s\n", domain);
}

void run_server(int sockfd) {
    char buffer[BUFFER_SIZE];
    struct sockaddr_in client_addr;
    socklen_t addr_len = sizeof(client_addr);

    while (1) {
        int n = recvfrom(sockfd, (char *)buffer, BUFFER_SIZE - 1, 0, (struct sockaddr *)&client_addr, &addr_len);
        if (n < 0) {
            perror("Error receiving message");
            continue;
        }

        buffer[n] = '\0';
        printf("DNS Query From Client: %s\n", inet_ntoa(client_addr.sin_addr));
        
        char domain[MAX_DOMAIN_LENGTH] = {0};
        parse_dns_query(buffer, n, domain);

        if (domain[0] != '\0') {
            if (is_domain_blocked(domain)) {
                printf("Blocked Domain: %s\n", domain);
                send_nxdomain_response(sockfd, &client_addr, addr_len, buffer, n);
            } else {
                printf("Forwarding Domain: %s\n", domain);
                forward_dns_query(sockfd, buffer, n, &client_addr, addr_len);
            }
        } else {
            printf("Invalid domain in query, ignoring request.\n");
        }
        printf("\n");
    }
}

int main() {
    int sockfd = create_UDP_socket();

    struct sockaddr_in server_addr = define_server_address();

    if (bind_server(sockfd, server_addr) < 0) {
        close(sockfd);  // Close the socket if binding fails
        exit(EXIT_FAILURE);
    }

    printf("DNS forwarder is running and listening on port %d...\n", PORT);

    run_server(sockfd);

    close(sockfd);
    return 0;
}

