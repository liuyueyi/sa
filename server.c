/*
 * server.c
 *
 *  Created on: 2014-8-29
 *      Author: wzb
 */
 
#include "server.h"

bool verify_client(int sockfd)
{
	char buffer[20];
	int len = 0;
	memset(buffer, 0, sizeof(buffer));
	
	srand((int)time(0));
	int n = rand() % 1000;
	sprintf(buffer, "%d", n); // generate a rand num
	
	if(send(sockfd, buffer, strlen(buffer), 0) != strlen(buffer))
		return false;
	
	if((len = recv(sockfd, buffer, 20, 0)) < 0)
		return false;
	int m = atoi(buffer);
	if(m == n)
		return true;
	else
		return false;
}

void receive_volume_key(int sockfd, const struct kmd_option *x)
{
	char buffer[LINE_MAX];
	int data_len;

	FILE *f;
	if((f = fopen(x->temp_pathname, "w")) == NULL)
	{
		fprintf(stderr, "crete temp file %s error\n", x->temp_pathname);
		exit(1);
	}
	
	memset(buffer, 0, LINE_MAX);
	while((data_len = recv(sockfd, buffer, LINE_MAX, 0)) >0)
	{
		if(data_len < LINE_MAX)
			buffer[data_len] = '\0';
		fwrite(buffer, sizeof(char), data_len, f);
	}
	fclose(f);
	
	FILE *fp = fopen(x->config_pathname, "r");
	if(NULL == fp)
	{
		fprintf(stderr, "%s used, try later\n", x->config_pathname);	
		exit(-1);
	}
	flock(fileno(f), LOCK_EX); //if locked, then wait
	flock(fileno(f), LOCK_UN); // unlcok and rename the file
	fclose(fp);
	rename(x->temp_pathname, x->config_pathname);
}


void send_volume_key(int sockfd, const struct kmd_option *x)
{
	char buffer[LINE_MAX];
	FILE *f;
	if((f = fopen(x->config_pathname, "r")) == NULL)
	{
		fprintf(stderr, "volume key pathname %s error\n", x->config_pathname);
		exit(1);
	}
	
	flock(fileno(f), LOCK_SH); // if file locked, then waited until it was unlocked

	while(fgets(buffer, LINE_MAX, f))
		send(sockfd, buffer, strlen(buffer), 0);

	flock(fileno(f), LOCK_UN);
	fclose(f);	
}



void server_process(int sockfd, const struct kmd_option *x)
{
	int data_len = 0;
	char buffer[1];

	// receive and judge the client request
	data_len = recv(sockfd, buffer, 1, 0); 
	if(data_len < 0)
	{
		fprintf(stderr, "receive error\n");
		exit(1);
	}
	int command = atoi(buffer);
	
	switch(command)
	{
		case 0: // receive file
			receive_volume_key(sockfd, x);
			break;
		case 1: // send file
			send_volume_key(sockfd, x);
			break;
		default:
			exit(1);
	}
}


void init_server(const struct kmd_option *x)
{
	int sockfd;
	int clientfd;
	uint16_t port = 10033;// x->port;
	
	struct sockaddr_in server_addr, client_addr;
	bzero(&server_addr, sizeof(server_addr));
	server_addr.sin_family = AF_INET;
	server_addr.sin_addr.s_addr  = htonl(INADDR_ANY);
	server_addr.sin_port = htons(port);
	
	if((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
	{
		fprintf(stderr, "open data stream socket failed!\n");
		exit(1);
	}
	
	if(bind(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
	{
		fprintf(stderr, "bind data socket failed!\n");
		exit(1);
	}
	
	if(listen(sockfd, SOMAXCONN) < 0)
	{
		fprintf(stderr, "listen data stream failed\n");
		exit(1);
	}
	
	while(1)
	{
		socklen_t len = sizeof(client_addr);
		clientfd = accept(sockfd, (struct sockaddr *)&client_addr, &len);
		if(clientfd < 0)
		{
			fprintf(stderr, "accept error\n");
			continue;
		}
		
		// if restrict the connected ip and the client ip is not the valid ip, then reject
		if(strlen(x->ip) > 0 && strcmp(x->ip, inet_ntoa(client_addr.sin_addr)) != 0)
		{
			close(clientfd);
			exit(0);
		}

		if(fork() == 0)
		{
			server_process(clientfd, x);
			exit(0);
		}
		close(clientfd);
	}
}
