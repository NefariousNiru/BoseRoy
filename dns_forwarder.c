#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <ctype.h>
#include <netinet/in.h>
#include <getopt.h>
#include <curl/curl.h>
#include <openssl/bio.h>
#include <openssl/evp.h>

#define PORT 9999
#define BUFFER_SIZE 2048
#define MAX_DENYLIST_SIZE 2048
#define MAX_DOMAIN_LENGTH 255
char denylist[MAX_DENYLIST_SIZE][MAX_DOMAIN_LENGTH];
int denylist_count = 0;
int use_doh = 0;   
char *denylist_file = NULL;
char *upstream_domain = "8.8.8.8";
char *log_file = NULL;
char *doh_server = "https://8.8.8.8";  

struct response_data {
    unsigned char *data;
    size_t size;
};

size_t write_callback(void *ptr, size_t size, size_t nmemb, void *userdata) {
    size_t realsize = size * nmemb;
    struct response_data *mem = (struct response_data *)userdata;

    unsigned char *ptr_new = realloc(mem->data, mem->size + realsize);
    if (ptr_new == NULL) {
        fprintf(stderr, "Not enough memory to realloc\n");
        return 0;
    }
    mem->data = ptr_new;

    memcpy(&(mem->data[mem->size]), ptr, realsize);
    mem->size += realsize;

    return realsize;
}

char *base64url_encode(const unsigned char *input, int length) {
    int encoded_length = 4 * ((length + 2) / 3);
    char *encoded_data = (char *)malloc(encoded_length + 1);

    if (encoded_data == NULL) {
        fprintf(stderr, "Memory allocation error\n");
        return NULL;
    }

    EVP_EncodeBlock((unsigned char *)encoded_data, input, length);

    for (int i = 0; i < encoded_length; i++) {
        if (encoded_data[i] == '+') encoded_data[i] = '-';
        else if (encoded_data[i] == '/') encoded_data[i] = '_';
    }

    encoded_data[encoded_length] = '\0';
    return encoded_data;
}

int send_doh_request(const unsigned char *dns_query, int query_len, unsigned char *response, int *response_len) {
    CURL *curl;
    CURLcode res;
    char *encoded_query = base64url_encode(dns_query, query_len);
    if (encoded_query == NULL) {
        fprintf(stderr, "Base64 URL encoding failed\n");
        return -1;
    }

    char url[512];
    snprintf(url, sizeof(url), "%s/dns-query?dns=%s", doh_server, encoded_query);
    free(encoded_query);

    curl = curl_easy_init();
    if (!curl) {
        fprintf(stderr, "Failed to initialize curl\n");
        return -1;
    }

    struct response_data chunk;
    chunk.data = malloc(1); 
    chunk.size = 0;          

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 5L);

    res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        fprintf(stderr, "DoH request failed: %s\n", curl_easy_strerror(res));
        curl_easy_cleanup(curl);
        free(chunk.data);
        return -1;
    }

    long response_code;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);

    *response_len = chunk.size;
    memcpy(response, chunk.data, chunk.size);

    curl_easy_cleanup(curl);
    free(chunk.data);
    printf("Using %s for DNS-over-Https", doh_server);
    return 0;
}

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
    printf("Using %s as Upstream Domain Server", upstream_domain);


    if ((resolver_sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("Resolver socket creation failed");
        return;
    }

    sendto(resolver_sock, buffer, length, 0, (struct sockaddr *)&resolver_addr, sizeof(resolver_addr));
    
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
        printf("\nDNS Query From Client: %s\n", inet_ntoa(client_addr.sin_addr));
        
        char domain[MAX_DOMAIN_LENGTH] = {0};
        parse_dns_query(buffer, n, domain);

        if (domain[0] != '\0') {
            if (is_domain_blocked(domain)) {
                printf("Blocked Domain: %s\n", domain);
                send_nxdomain_response(sockfd, &client_addr, addr_len, buffer, n);
            } else {
                printf("Forwarding Domain: %s\n", domain);
                if (use_doh) {
                    unsigned char doh_response[BUFFER_SIZE];
                    int doh_response_len;
                    if (send_doh_request((unsigned char *)buffer, n, doh_response, &doh_response_len) == 0) {
                        sendto(sockfd, doh_response, doh_response_len, 0, (struct sockaddr *)&client_addr, addr_len);
                    } else {
                        printf("DoH request failed\n");
                    }
                } else {
                    forward_dns_query(sockfd, buffer, n, &client_addr, addr_len);
                }
            }
        } else {
            printf("Invalid domain in query, ignoring request.\n");
        }
        printf("\n");
    }
}

void print_usage(char *program_name) {
    printf("Usage: %s [-f denylist_file] [-d dns_server] [-l log_file] [--doh] [--doh_server <url>]\n", program_name);
    printf("\nOptions:\n");
    printf("  -h, --help                   Show this help message and exit\n");
    printf("  -f DENY_LIST_FILE            File containing domains to block\n");
    printf("  -d DST_IP                    Destination DNS server IP\n");
    printf("  -l LOG_FILE                  Append-only log file\n");
    printf("  --doh                         Use default upstream DoH server\n");
    printf("  --doh_server DOH_SERVER       Use this upstream DoH server\n");
    printf("\nRequirements:\n");
    printf("If --doh or --doh_server are specified, the forwarder MUST forward the DNS query using the DoH protocol\n");
    printf("If neither --doh nor --doh_server are specified (in which case -d MUST be present), the forwarder MUST forward the DNS query using the DNS protocol\n");
    printf("The DNS forwarder MUST receive DNS messages from the client via a simple UDP server socket.\n");
    printf("When DoH is not used, the -d option will be specified and the forwarder must use a simple UDP client socket to forward the client's query to the DNS resolver\n");
    printf("The DENY_LIST_FILE file MUST contain a (potentially empty) list of domain names that MUST be blocked by the forwarder.\n");
}

void parse_arguments(int argc, char *argv[]){
    int opt;
    static struct option long_options[] = {
        {"help", no_argument, 0, 'h'},           // Support `--help`
        {"doh", no_argument, &use_doh, 1},       // Sets `use_doh` to 1 if `--doh` is provided
        {"doh_server", required_argument, 0, 's'}, // Custom DoH server
        {0, 0, 0, 0}
    };

    while ((opt = getopt_long(argc, argv, "hf:d:l:", long_options, NULL)) != -1) {
        switch (opt) {
            case 'h':
                print_usage(argv[0]);
                exit(0);
                break;
            case 'f':
                denylist_file = optarg;
                printf("Denylist file: %s\n", denylist_file);
                break;
            case 'd':
                upstream_domain = optarg;  // Use `upstream_domain` consistently
                printf("DNS server: %s\n", upstream_domain);
                break;
            case 'l':
                log_file = optarg;
                printf("Log file: %s\n", log_file);
                break;
            case 0:
                if (strcmp("doh_server", long_options[optind - 1].name) == 0) {
                    const char *prefix = "https://";
                    size_t url_length = strlen(prefix) + strlen(optarg) + 1;
                    doh_server = (char *)malloc(url_length);
                    if (!doh_server) {
                        perror("Memory allocation for DoH server failed");
                        exit(EXIT_FAILURE);
                    }
                    snprintf(doh_server, url_length, "%s%s", prefix, optarg);
                    printf("DoH server: %s\n", doh_server);
                } else if (strcmp("doh", long_options[optind - 1].name) == 0) {
                    printf("DoH enabled\n");
                }
                break;
            default:
                print_usage(argv[0]);
                exit(EXIT_FAILURE);
        }
    }
}

int main(int argc, char *argv[]) {
    parse_arguments(argc, argv);

    if (denylist_file != NULL) {
        load_denylist(denylist_file);
    }

    printf("DNS forwarder running on port %d...\n", PORT);
    printf("Using DoH: %s\n", use_doh ? "Enabled" : "Disabled");
    if (use_doh) {
        printf("DoH Server: %s\n", upstream_domain);
    }

    int sockfd = create_UDP_socket();

    struct sockaddr_in server_addr = define_server_address();

    if (bind_server(sockfd, server_addr) < 0) {
        close(sockfd);  // Close the socket if binding fails
        exit(EXIT_FAILURE);
    }

    run_server(sockfd);
    free(doh_server);
    close(sockfd);
    return 0;
}

