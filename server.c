/*
 * server.c
 *
 *  Created on: 2014-8-29
 *      Author: wzb
 */

#include "server.h"
#include "rsa.h"

bool verify_client(int sockfd)
{
	char buffer[20];
	int len = 0;
	memset(buffer, 0, sizeof(buffer));

	srand((int) time(0));
	int n = rand() % 1000;
	sprintf(buffer, "%d", n); // generate a rand num

	if (send(sockfd, buffer, strlen(buffer), 0) != strlen(buffer))
		return false;

	if ((len = recv(sockfd, buffer, 20, 0)) < 0)
		return false;
	int m = atoi(buffer);
	if (m == n)
		return true;
	else
		return false;
}

void receive_volume_key(int sockfd, const struct kmd_option *x)
{
	char buffer[LINE_MAX];
	int data_len;
	char digest[29];
	if ((data_len = recv(sockfd, digest, 28, 0)) != 28)
	{
		fprintf(stderr, "receive digest error\n");
		exit(1);
	}

	FILE *f;
	if ((f = fopen(x->temp_pathname, "w")) == NULL )
	{
		fprintf(stderr, "crete temp file %s error\n", x->temp_pathname);
		exit(1);
	}

	while ((data_len = recv(sockfd, buffer, LINE_MAX, 0)) > 0)
		fwrite(buffer, sizeof(char), data_len, f);

	fclose(f);

	char result[30];
	sha1(x->config_pathname, result, 30);
	if (strcmp(digest, result) != 0)
	{
		fprintf(stderr, "verify volume key's integrity failed!\n");
		exit(1);
	}
	rename(x->temp_pathname, x->config_pathname);
}

void send_volume_key(int sockfd, const struct kmd_option *x)
{
	char buffer[LINE_MAX];
	FILE *f;
	if ((f = fopen(x->config_pathname, "r")) == NULL )
	{
		fprintf(stderr, "volume key pathname %s error\n", x->config_pathname);
		exit(1);
	}

	flock(fileno(f), LOCK_SH); // if file locked, then waited until it was unlocked

	char result[30];
	sha1(x->config_pathname, result, 30); // 错误判断
	send(sockfd, result, strlen(result), 0); // send digest

	while (fgets(buffer, LINE_MAX, f))
	{
		send(sockfd, buffer, strlen(buffer), 0);
	}

	flock(fileno(f), LOCK_UN);
	fclose(f);
}

void server_process(int sockfd, const struct kmd_option *x)
{
	int data_len = 0;
	char cmd;

	// receive and judge the client request
	data_len = recv(sockfd, &cmd, 1, 0);
	if (data_len < 0)
	{
		fprintf(stderr, "receive error\n");
		exit(1);
	}
	switch (cmd)
	{
	case 'R': // receive file
		receive_volume_key(sockfd, x);
		break;
	case 'T': // send file
		send_volume_key(sockfd, x);
		break;
	default:
		exit(1);
	}
}

#define SIGFREE 0
#define SIGBUSY 1
int busy = 0;
void sigroutine(int signo)
{
    switch (signo)
    {
        case SIGBUSY:
            busy = 1;
            break;
        case SIGFREE:
            busy = 0;
            break;
    }
    return;
}

void server_work(int sockfd)
{
	int clientfd;
	struct sockaddr_in client_addr;
	while (1)
	{
		socklen_t len = sizeof(client_addr);
		clientfd = accept(sockfd, (struct sockaddr *) &client_addr, &len);
		if (clientfd < 0)
		{
			fprintf(stderr, "accept error\n");
			continue;
		}

		if (busy == 1)
		{
			// socket busy
			continue;
		}

		signature(SIGBUSY, sigroutine);
		int x = fork();
		if (x < 0)
		{
			// error
			signature(SIGFREE, sigroutine);
		}
		else if (0 == x)
		{
			server_process(clientfd, x);
			signature(SIGFREE, sigroutine);
			exit(0);
		}
		close(clientfd);
	}
}

int init_server(const struct kmd_option *x)
{
	int sockfd;
	int clientfd;
	uint16_t port = x->port;

	struct sockaddr_in server_addr;
	bzero(&server_addr, sizeof(server_addr));
	server_addr.sin_family = AF_INET;
	server_addr.sin_addr.s_addr = inet_addr(x->ip);
	server_addr.sin_port = htons(port);

	if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
	{
		fprintf(stderr, "open data stream socket failed!\n");
		exit(1);
	}

	if (bind(sockfd, (struct sockaddr *) &server_addr, sizeof(server_addr)) < 0)
	{
		fprintf(stderr, "bind data socket failed!\n");
		exit(1);
	}

	if (listen(sockfd, SOMAXCONN) < 0)
	{
		fprintf(stderr, "listen data stream failed\n");
		exit(1);
	}

	return sockfd;
}
