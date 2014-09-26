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
			return -errno;
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
			return -errno;
	}
	else if (size < len)
		return size + sendn(fd, buf + size, len - size, flag);

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

char *insert_method(char *buf, size_t size, char *method, size_t m_len)
{
	char temp[PATH_MAX];
	strcpy(temp, buf);

	int len = strlen(buf);
	if (len + m_len + 2 > size)
	{
		fprintf(stderr, "pathname too long (%s)\n", buf);
		return NULL ;
	}

	while (len > 0 && buf[len - 1] != '/')
		len--;
	buf[len] = '\0';
	strcat(buf, method);
	strcat(buf, "_");
	strcat(buf, temp + len);
	return buf;
}

#ifndef EN
#define EN
struct encrypt_operations *en;
#endif
bool init_encrypt_method(char *method, size_t size, struct kmd_option *x)
{
	remove_space(method, size);
	int len = strlen(method);
	if ((NULL == insert_method(x->pk_pathname, PATH_MAX, method, len))
			|| (NULL == insert_method(x->sk_pathname, PATH_MAX, method, len))
			|| (NULL == insert_method(x->config_pathname, PATH_MAX, method, len))
			|| (NULL == insert_method(x->temp_pathname, PATH_MAX, method, len)))
		goto err;

	en = set_encryption_method(method, x->sk_pathname, x->pk_pathname);
	if (NULL == en)
		goto err;

	return true;

	err:
	print_dbg(0, "encrypt method(%s) error\n", method);
	record_log("encrypt method(%s) error\n", method);
	return false;
}

int response_to_kmc(int sockfd, char ret, const char *err_info)
{
	char res[2];
	res[0] = ret;
	res[1] = '\n';
	if (sendn(sockfd, res, 2, 0) < 0)
	{
		print_dbg(1, err_info);
		return -1;
	}
	return 0;
}

bool verify_client(int sockfd, struct kmd_option *x)
{
	char buffer[20];
	int len = 0;
	/*
	 * verify KMC's identity
	 * 1. receive the encrypt method(such as: rsa, sm)
	 * 2. generate a random number: n
	 * 3. encrypt the random with KMC's public key
	 * 4. receive KMC return the random:m
	 * 5. compare n and m
	 * 6. n == m : KMC legal, and response "Y\n" to KMC
	 * 7. n != m : KMC illegal, and response "N\n" to KMC
	 */
	if ((len = recvn(sockfd, buffer, 20, 0)) < 0) // receive encrypt method
	{
		print_dbg(0, "receive connect protocol from ip=%s error\n", client_ip);
		return false;
	}
	if (!init_encrypt_method(buffer, 20, x))
		return false;

	srand((int) time(0));
	int n = rand() % 1000;
	sprintf(buffer, "%d", n); // generate a random 
	print_dbg(1, "the randmom is %d\n", n);

	char cipher[1024];
	if (NULL == (*(en->encrypt))(buffer, cipher, 1024, x->pk_pathname))
	{
		print_dbg(0, "encrypt random number error\n");
		return false;
	}
	size_t c_len = strlen(cipher);
	cipher[c_len] = '\n';
	cipher[c_len + 1] = '\0';
	if (sendn(sockfd, cipher, c_len + 1, 0) != c_len + 1)
	{
		print_dbg(0, "send random number to ip=%s error\n", client_ip);
		return false;
	}

	char receive[5];
	if ((len = recvn(sockfd, receive, 5, 0)) < 0) //receive the plain number
	{
		print_dbg(0, "receive random number from ip=%s error\n", client_ip);
		return false;
	}
	int m = atoi(receive);
	print_dbg(1, "(random %d) (receive %d)\n", n, m);

	char ret = 'N';
	if (m == n)
		ret = 'Y';
	print_dbg(1, "verify result(Y:succeed / N:failed): %c\n", ret);
	if (-1 == response_to_kmc(sockfd, ret, "verify result error\n"))
		return false;

	/*
	 *  below: KMC verify sa's identity
	 *  1. receive cipher
	 *  2. decrypt the cipher with sa's private key
	 *  3. send the plain text to KMC
	 *  4. receive kmc's response (Y:succeed/N:fail)
	 */
	char num[200];
	if ((len = recvn(sockfd, num, 200, 0)) < 0) // receive cipher
	{
		print_dbg(0, "receive kmc(ip=%s) cipher random number error\n", client_ip);
		return false;
	}
	char ans[50];
	if (NULL == (*(en->decrypt))(num, ans, 50, x->sk_pathname))
	{
		print_dbg(0, "decrypt the kmc(ip=%s) random number error\n", client_ip);
		return false;
	}
	print_dbg(1, "the receive random number is %s\n", ans);
	len = strlen(ans);
	ans[len] = '\n';
	if ((len = sendn(sockfd, ans, len + 1, 0)) < 0)
	{
		print_dbg(0, "send random number to ip=%s error\n", client_ip);
		return false;
	}
	char r;
	if ((len = recvn(sockfd, &r, 1, 0)) < 0 || (r != 'Y' && r != 'y'))
	{
		print_dbg(0, "receive kmc's response error(ret=%c)\n", r);
		return false;
	}
	print_dbg(1, "receive kmc's response = %c\n", r);

	return r == 'Y' ? true : false;
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

// judge if line is in the file
bool in_file(FILE *f, char *line)
{
	bool tag = false;
	if (-1 == fseek(f, 0, SEEK_SET))
		in_file(f, line);

	char buf[LINE_MAX];
	while (fgets(buf, LINE_MAX, f))
	{
		if (strstr(buf, line) != NULL )
		{
			print_dbg(1, "already have volume key : %s\n", line);
			tag = true;
			break;
		}
		tag = false;
	}
	return tag;
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
	{
		// if exist, then ignore this volume key
		if (!in_file(cf, line))
			fputs(line, cf);
	}

	flock(fileno(cf), LOCK_UN);
	fclose(cf);
	fclose(tf);
	return remove(x->temp_pathname);
}

/*
 * receive data from kmc's process flow:
 *   1. receive sha1 digest(28byte)
 *   2. receive content's size(20byte, if less then 20, then filling in non-digit number)
 *   3. calculate the loop receive times
 *   4. receive the content and save them in tempt file
 *   5. calculate the tempt file's sha1 digest
 *   6. compare the two digest
 *   7. response Y or N to KMC
 *   8. if response is Y, append or replace the receive data
 */
int receive_volume_key(int sockfd, const struct kmd_option *x,
		int (*puc)(const struct kmd_option *x))
{
	char buffer[LINE_MAX];
	int data_len;
	char digest[29];
	// receive the data's sha1 digest
	if ((data_len = recvn(sockfd, digest, 28, 0)) < 0)
	{
		record_log("receive data digest from ip=%s error\n", client_ip);
		print_dbg(0, "receive data digest from ip=%s error\n", client_ip);
		return data_len;
	}
	digest[28] = '\0';
	print_dbg(1, "receive digest = %s\n", digest);

	FILE *f; // temp file to save the receive data
	if ((f = fopen(x->temp_pathname, "w")) == NULL )
	{
		record_log("create temp file %s failed\n", x->temp_pathname);
		print_dbg(0, "create temp file %s failed\n", x->temp_pathname);
		return -1;
	}

	char size[20];
	if ((data_len = recvn(sockfd, size, 20, 0)) < 0)
	{
		record_log("receive content size from ip%s error\n", client_ip);
		remove(x->temp_pathname);
		return -1;
	}
	long s = atol(size); // get the receive data length, and calculate the loop time
	int count = s / LINE_MAX;

	while ((data_len = recvn(sockfd, buffer, LINE_MAX, 0)) > 0)
	{
		fwrite(buffer, sizeof(char), data_len, f);
		if (--count < 0)
			break;
	}
	fclose(f);

	if (data_len < 0) // receive data error
	{
		record_log("receive data from ip:%s error\n", client_ip);
		remove(x->temp_pathname);
		return data_len;
	}

	char ret = 'N';
	char result[29];
	if (NULL == (*(en->sha1))(x->temp_pathname, result, 29, x->pk_pathname))
	{
		print_dbg(0, "failed to calculate receive data's sha1 digest\n");
		record_log("failed to calculate receive data's sha1 digest\n", NULL );
		goto RESPONSE;
	}
	print_dbg(1, "calculate sha1 = %s\n", result);

	if (strcmp(digest, result) != 0)
	{
		print_dbg(0, "receive data's integrity verify failed\n");
		record_log("receive data's integrity verify failed\n", NULL );
		goto RESPONSE;
	}
	ret = 'Y';

	RESPONSE: if (response_to_kmc(sockfd, ret, "receive data error") < 0
			|| ret == 'N')
	{
		remove(x->temp_pathname);
		return -1;
	}

	return puc(x);
}

/*
 * send data to kmc for backing up
 *   1. calculate the key file's sha1 digest
 *   2. send sha1 digest to kmc
 *   3. read key file's data and send to kmc
 *   4. send end tag "##end\n" to kmc
 *   5. receive kmc's response(Y:succeed\N:failed)
 */
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
		print_dbg(0, "send sha1 digest to ip=%s error\n", client_ip);
		return record_log("send sha1 digest tp ip=%s error\n", client_ip);
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

	if (sendn(sockfd, "##end\n", 6, 0) < 0)
	{
		return record_log("send end tag to ip=%s failed\n", client_ip);
	}

	char ret;
	if (recvn(sockfd, &ret, 1, 0) < 0 || ret != 'Y')
		return record_log("kmc receive volume key from ip=%s error\n",
				client_ip);

	print_dbg(1, "kmc response(Y/N) = %c\n", ret);
	return size;
}

void server_process(int sockfd, struct kmd_option *x)
{
	int data_len = 0;
	char cmd;

	// receive and judge the kmc's request
	data_len = recvn(sockfd, &cmd, 1, 0);
	if (data_len < 0)
	{
		record_log("receive request from ip=%s error\n", client_ip);
		return;
	}

	print_dbg(1, "command from ip=%s is \'%c\'\n", client_ip, cmd);
	switch (cmd)
	{
	case 'A': // append to original file
		if(receive_volume_key(sockfd, x, append_tempfile) < 0)
			record_log("%s: add request failed\n", client_ip);
		else
			record_log("%s: add request succeed\n", client_ip);
		break;
	case 'R': // receive file
		if(receive_volume_key(sockfd, x, rename_tempfile) < 0)
			record_log("%s: recover request failed\n", client_ip);
		else
			record_log("%s: recover request succeed\n", client_ip);
		break;
	case 'T': // send file
		if(send_volume_key(sockfd, x) < 0)
			record_log("%s: backup request failed\n", client_ip);
		else
			record_log("%s: recover request succeed\n", client_ip);
		break;
	default:
		record_log("command \'%c\' is illegal\n", (void *) cmd);
		break;
	}
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
			// record the client ip
			strcpy(client_ip, inet_ntoa(client_addr.sin_addr));
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

	int flag = 1;
	if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &flag, sizeof(flag)) < 0)
	{
		fprintf(stderr, "set reused socket failed!\n");
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
