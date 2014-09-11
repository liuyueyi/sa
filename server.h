/*
 * server.h
 *
 *  Created on: 2014-8-29
 *      Author: wzb
 */

#ifndef SERVER_H_
#define SERVER_H_

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/file.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <limits.h>
#include <stdbool.h>

struct kmd_option
{
	bool debug;
	uint16_t port;
	char ip[16];
	
	char sk_pathname[PATH_MAX];
	char pk_pathname[PATH_MAX];
	char config_pathname[PATH_MAX];
	char temp_pathname[PATH_MAX];
};


int init_server();

void server_work(int fd);

#endif /* SERVER_H_ */
