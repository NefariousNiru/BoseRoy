# Define the compiler
CC = gcc

# Define compiler flags
CFLAGS = -Wall -g

# Define linker flags for OpenSSL
LDFLAGS = -lssl -lcrypto

# Define the target executable
TARGET = dns_forwarder

# Define source files
SRCS = dns_forwarder.c

# Define object files
OBJS = $(SRCS:.c=.o)

# Default target: build the executable
all: $(TARGET)

# Rule to build the executable
$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJS) $(LDFLAGS)

# Rule to build object files
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# Clean up the build files
clean:
	rm -f $(OBJS) $(TARGET)

# Phony targets to avoid conflicts with filenames
.PHONY: all clean