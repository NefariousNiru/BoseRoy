#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <ctype.h>

#define PORT 9999
#define BUFFER_SIZE 1024

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

void parse_dns_query(char *buffer, int length) {
    // First 12 bytes for DNS Header
    int header_size = 12;

    if (length < header_size) {
        printf("Invalid Length DNS Message\n");
        return;
    }

    char *qname = buffer + header_size;
    char *end_msg = buffer + length;

    printf("Requested Domain: ");
    while (qname < end_msg && *qname != 0) {
        int label_len = *qname;

        if (label_len < 0 || qname + label_len >= end_msg) {
            printf("\nError: Label length exceeds message bounds or is invalid\n");
            return;
        }

        qname++;

        for (int i = 0; i < label_len; i++) {
            if (qname >= end_msg || (!isalnum(*qname) && *qname != '-')) {
                printf("\nError: Unexpected character in domain name '%s'\n", qname);
                return;
            }
            printf("%c", *qname);
            qname++;
        }

        if (*qname != 0) printf(".");
    }
    printf("\n");
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
        printf("Received DNS query from client\n");

        parse_dns_query(buffer, n);

        sendto(sockfd, buffer, n, 0, (struct sockaddr *)&client_addr, addr_len);
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

