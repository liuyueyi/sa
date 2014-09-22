/*
 * server.c
 *
 *  Created on: 2014-8-29
 *      Author: wzb
 */

#include "server.h"
#include "rsa.h"

int dbg_level = -1;
#define print_dbg(level, ...)						\
	({								\
	if (level <= dbg_level) {					\
		fprintf(stderr, "%s, %u, %s: ",				\
			__FILE__, __LINE__, __func__);			\
		fprintf(stderr, ##__VA_ARGS__);				\
	}								\
	})

int record_log(char *info, const char *ptr)
{
	openlog("kmdLog", LOG_CONS | LOG_PID, 0);
	syslog(LOG_USER | LOG_INFO, info, ptr);
	closelog();
	return -1;
}

char client_ip[16];
int recvn(int fd, char *buf, size_t len, int flag)
{
	int size = recv(fd, buf, len, flag);
	if (size < 0)
	{
		if (errno == EINTR)
			return recvn(fd, buf, len, flag);
		else
		{
			record_log("receive data from ip:%s error\n", client_ip);
			print_dbg(0, "receive data from ip:%s error\n", client_ip);
			return -errno;
		}
	}
	return size;
}

int sendn(int fd, const char *buf, size_t len, int flag)
{
	int size = send(fd, buf, len, flag);
	if (size < 0)
	{
		if (errno == EINTR)
			return sendn(fd, buf, len, flag);
		else
		{
			record_log("send data to ip:%s error\n", client_ip);
			print_dbg(0, "receive data from ip:%s error\n", client_ip);
			return -errno;
		}
	}
	return size;
}

/**
 * remove the begin and end space of the buf, and inter buf there is no space character
 * for example: 
 *  buf="  rsa \n\t ", then you will get buf="rsa"
 *  buf=" rsa sm \n"    this buf type is illegal
 */
void remove_space(char *buf, size_t len)
{
	int i = 0, j = 0;
	bool tag = false;
	while (i < len)
	{
		if (!isspace(buf[i])) // not space
		{
			tag = true;
			buf[j++] = buf[i++];
			continue;
		}

		if (tag)
			break;
		++i;
	}
	buf[j] = '\0';
}

#ifndef EN
#define EN
struct encrypt_operations *en;
#endif
bool init_encrypt_method(char *buffer, struct kmd_option *x)
{
	remove_space(buffer, 20);
	en = set_encryption_method(buffer, x->sk_pathname, x->pk_pathname);
	if (en == NULL )
	{
		print_dbg(0, "encrypt method(%s) error\n", buffer);
		record_log("encrypt method(%s) error\n", buffer);
		return false;
	}
	return true;
}

bool verify_client(int sockfd, struct kmd_option *x)
{
	char buffer[20];
	int len = 0;

	if ((len = recvn(sockfd, buffer, 20, 0)) < 0)
	{
		print_dbg(0, "receive connect protocol error\n");
		return false;
	}
	if (!init_encrypt_method(buffer, x))
		return false;

	srand((int) time(0));
	int n = rand() % 1000;
	sprintf(buffer, "%d", n); // generate a random 
	print_dbg(1, "the randmom is %d\n", n);

	char cipher[500];
	if (NULL == (*(en->encrypt))(buffer, cipher, 500, x->pk_pathname))
	{
		print_dbg(0, "encrypt random number error\n");
		return false;
	}
	cipher[strlen(cipher)] = '\n';
	cipher[strlen(cipher) + 1] = '\0';
	if (sendn(sockfd, cipher, strlen(cipher), 0) != strlen(cipher))
	{
		print_dbg(0, "send random number error\n");
		return false;
	}

	char receive[20];
	if ((len = recvn(sockfd, receive, 20, 0)) < 0)
	{
		print_dbg(0, "receive random number error\n");
		return false;
	}
	int m = atoi(receive);

	print_dbg(1, "(random %d) (receive %d)\n", n, m);
	char ret[2];
	if (m == n)
	{
		ret[0] = 'Y';
		print_dbg(1, "verify client legal\n");
	}
	else
	{
		ret[0] = 'N';
		print_dbg(1, "verify client illegal\n");
	}
	ret[1] = '\n';

	if ((len = sendn(sockfd, ret, 2, 0)) < 0)
	{
		print_dbg(1, "send verify result error\n");
		return false;
	}

	return ret[0] == 'Y' ? true : false;
}

int rename_tempfile(const struct kmd_option *x)
{
	FILE *fp;
	// if not exist
	if (access(x->config_pathname, F_OK) < 0)
	{
		rename(x->temp_pathname, x->config_pathname);
		return 0;
	}

	if (NULL == (fp = fopen(x->config_pathname, "r")))
	{
		record_log("save receive data to %s failed\n", x->config_pathname);
		print_dbg(0, "save receive data to %s failed\n", x->config_pathname);
		return -1;
	}

	flock(fileno(fp), LOCK_EX);
	rename(x->temp_pathname, x->config_pathname);
	flock(fileno(fp), LOCK_UN);
	fclose(fp);
	return 0;
}

int append_tempfile(const struct kmd_option *x)
{
	FILE *cf;
	FILE *tf;

	if (NULL == (cf = fopen(x->config_pathname, "a+"))
			|| NULL == (tf = fopen(x->temp_pathname, "r")))
	{
		record_log("save receive data to %s failed\n", x->config_pathname);
		print_dbg(0, "save receive data to %s failed\n", x->config_pathname);
		return -1;
	}

	flock(fileno(cf), LOCK_EX);
	char line[LINE_MAX];
	while (fgets(line, LINE_MAX, tf))
		fputs(line, cf);

	flock(fileno(cf), LOCK_UN);
	fclose(cf);
	fclose(tf);
	return remove(x->temp_pathname);
}

int receive_volume_key(int sockfd, const struct kmd_option *x,
		int (*puc)(const struct kmd_option *x))
{
	char buffer[LINE_MAX];
	int data_len;
	char digest[29];
	// receive the data sha1 digest
	if ((data_len = recvn(sockfd, digest, 28, 0)) < 0)
	{
		record_log("receive data digest error\n", NULL );
		print_dbg(0, "receive data digest error\n");
		return data_len;
	}
	digest[28] = '\0';
	print_dbg(1, "digest=%s\n", digest);

	FILE *f;
	if ((f = fopen(x->temp_pathname, "w")) == NULL )
	{
		record_log("create temp file %s failed\n", x->temp_pathname);
		print_dbg(0, "create temp file %s failed\n", x->temp_pathname);
		return -1;
	}

	while ((data_len = recvn(sockfd, buffer, LINE_MAX, 0)) > 0)
		fwrite(buffer, sizeof(char), data_len, f);
	fclose(f);

	if (data_len < 0) // receive data error
	{
		record_log("receive data from ip:%s error\n", client_ip);
		remove(x->temp_pathname);
		return data_len;
	}

	char result[29];
	if (NULL == (*(en->sha1))(x->temp_pathname, result, 30, x->pk_pathname))
	{
		print_dbg(0, "failed to calculate receive data's sha1 digest\n");
		return record_log("failed to calculate receive data's sha1 digest\n",
				NULL );
	}
	print_dbg(1, "sha1=%s\n", result);

	if (strcmp(digest, result) != 0)
	{
		print_dbg(0, "receive data's integrity verify failed\n");
		record_log("receive data's integrity verify failed\n", NULL );
		return false;
	}

	return puc(x);
}

int send_volume_key(int sockfd, const struct kmd_option *x)
{
	FILE *f;
	int size;
	char buffer[LINE_MAX];
	char result[30];

	// calculate and send sha1 digest for integrity verify
	if (NULL == (*(en->sha1))(x->config_pathname, result, 30, x->pk_pathname))
	{
		print_dbg(0, "calculate sha1 digest error\n");
		return record_log("calculate sha1 digest error\n", NULL );
	}
	print_dbg(1, "the sha1 digest is : %s\n", result);
	result[28] = '\n';

	if (sendn(sockfd, result, 29, 0) < 0)
	{
		print_dbg(0, "send sha1 digest error\n");
		return record_log("send sha1 digest error\n", NULL );
	}

	if ((f = fopen(x->config_pathname, "r")) == NULL )
	{
		print_dbg(0, "%s volume key file not exist!\n", x->config_pathname);
		return record_log("%s volume key file not exist!\n", x->config_pathname);
	}

	flock(fileno(f), LOCK_SH); // if file locked, then waited until it was unlocked
	while (fgets(buffer, LINE_MAX, f))
	{
		if ((size = sendn(sockfd, buffer, strlen(buffer), 0)) < 0)
			break;
	}

	flock(fileno(f), LOCK_UN);
	fclose(f);
	return size;
}

void server_process(int sockfd, struct kmd_option *x)
{
	int data_len = 0;
	char cmd;

	// receive and judge the client request
	data_len = recvn(sockfd, &cmd, 1, 0);
	if (data_len < 0)
		return;

	print_dbg(1, "command from ip=%s is \'%c\'\n", client_ip, cmd);
	switch (cmd)
	{
	case 'A': // append to original file
		receive_volume_key(sockfd, x, append_tempfile);
		break;
	case 'R': // receive file
		receive_volume_key(sockfd, x, rename_tempfile);
		break;
	case 'T': // send file
		send_volume_key(sockfd, x);
		break;
	default:
		record_log("command \'%c\' is illegal\n", (void *) cmd);
		break;
	}

	print_dbg(2, "response client request over\n");
	free(en);
	en = NULL;
}

int busy = 0;
static void signal_handler(int sig)
{
	int stat;
	pid_t pid;

	while ((pid = waitpid(-1, &stat, WNOHANG)) > 0)
		;
	busy = 0;
}

void server_work(int sockfd, struct kmd_option *x)
{
	int clientfd;
	struct sockaddr_in client_addr;

	signal(SIGCHLD, signal_handler);
	while (1)
	{
		socklen_t len = sizeof(client_addr);
		if ((clientfd = accept(sockfd, (struct sockaddr *) &client_addr, &len))
				< 0)
		{
			if (EINTR == clientfd)
				continue;
			else
			{
				print_dbg(0,
						"accept from ip:%s error\n", inet_ntoa(client_addr.sin_addr));
				record_log("accept from ip:%s error\n",
						inet_ntoa(client_addr.sin_addr));
			}
		}
		// record the client ip
		strcpy(client_ip, inet_ntoa(client_addr.sin_addr));

		if (busy == 1)
		{
			print_dbg(1, "socket busy\n");
			record_log("socket busy\n", NULL );
			close(clientfd);
			sleep(1);
			continue;
		}

		busy = 1;
		int i = fork();
		if (i < 0)
		{
			print_dbg(0, "create child process failed\n");
			record_log("create child process failed\n", NULL );
			busy = 0;
		}
		else if (0 == i)
		{
			if (!verify_client(clientfd, x))
			{
				print_dbg(1,
						"illegal ip:%s try to connect the server, and reject\n", client_ip);
				record_log(
						"illegal ip:%s try to connect the server, and reject\n",
						client_ip);
				exit(0);
			}

			server_process(clientfd, x);
			exit(0);
		}
		close(clientfd);
	}
}

int init_server(const struct kmd_option *x)
{
	int sockfd;
	uint16_t port = x->port;

	struct sockaddr_in server_addr;
	bzero(&server_addr, sizeof(server_addr));
	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(port);
	if (strcmp(x->ip, "INADDR_ANY") == 0)
		server_addr.sin_addr.s_addr = htonl(INADDR_ANY );
	else
		server_addr.sin_addr.s_addr = inet_addr(x->ip);

	if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
	{
		fprintf(stderr, "open data stream socket failed!\n");
		return -errno;
	}

	if (bind(sockfd, (struct sockaddr *) &server_addr, sizeof(server_addr)) < 0)
	{
		fprintf(stderr, "failed to bind socket port:%d\n", port);
		return -errno;
	}

	if (listen(sockfd, SOMAXCONN) < 0)
	{
		fprintf(stderr, "listen data stream failed\n");
		return -errno;
	}

	print_dbg(0, "init server succeed\n");
	print_dbg(1,
			"sa server ip=%s, port=%d\n", inet_ntoa(server_addr.sin_addr), port);
	return sockfd;
}
