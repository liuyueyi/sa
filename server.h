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
#include <sys/wait.h>
#include <stdbool.h>
#include <ctype.h>
#include <unistd.h>
#include <time.h>
#include <stdbool.h>
#include <syslog.h>
#include <signal.h>

#include "encrypt.h"

struct kmd_option
{
	uint16_t port;
	bool debug;
	bool no_verify;
	int debug_level;
	char ip[16];

	char sk_pathname[PATH_MAX];
	char pk_pathname[PATH_MAX];
	char config_pathname[PATH_MAX];
	char temp_pathname[PATH_MAX];
};

int init_server();

void server_work(int fd, struct kmd_option *x);

#endif /* SERVER_H_ */
