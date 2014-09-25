#include "server.h"
#include <getopt.h>
#define pid_pathname "/var/run/kmd.pid"

struct option const long_options[] =
{
{ "ip", required_argument, NULL, 'i' },
{ "port", required_argument, NULL, 'p' },
{ "config_pathname", required_argument, NULL, 'c' },
{ "sk_pathname", required_argument, NULL, 'S' },
{ "pk_pathname", required_argument, NULL, 'P' },
{ "help", no_argument, NULL, 'h' },
{ "debug", required_argument, NULL, 'd' },
{ NULL, 0, NULL, 0 } };

#define CONFIG_FILENAME "key.conf"
#define TEMP_FILENAME "key.conf.tm"
#define SK_FILENAME "kmc_priv.key"
#define PK_FILENAME "kmc_pub.key"
#define DEFAULT_PORT 10033

extern int dbg_level;
void kmd_option_init(struct kmd_option *x)
{
	x->debug = false;
	x->port = DEFAULT_PORT;
	strcpy(x->ip, "INADDR_ANY");
	strcpy(x->sk_pathname, SK_FILENAME);
	strcpy(x->pk_pathname, PK_FILENAME);
	strcpy(x->config_pathname, CONFIG_FILENAME);
	strcpy(x->temp_pathname, TEMP_FILENAME);
}

void do_help()
{
	printf(("Usage: kmd [OPTION]... \n"));
	fputs(("\
key management storage agent.\n\
\n\
"), stdout);
	fputs(
			("\
Mandatory arguments to long options are mandatory for short options too.\n\
"),
			stdout);
	fputs(
			("\
  -i, --ip=x.x.x.x      limit the connect ip .\n\
                        egg:\n\
                          kmd -i 192.168.0.1 \n\
"),
			stdout);
	fputs(
			("\
  -p, --port=10033      set the bind port \n\
                        egg:\n\
                          kmd -p 10030\n\
"),
			stdout);
	fputs(
			("\
  -c, --config_pathname key file pathname\033[47;31m[default=key.conf]\033[0m\n\
                        egg:\n\
                          if the original pathname = rsa_key.conf, then set volume key pathname like this:\n\
                          kmd -c key.conf\n\
"),
			stdout);
	fputs(
			("\
  -P, --pk_pathname     public key pathname\033[47;31m[default=kmc_pub.key]\033[0m\n\
                        egg:\n\
                          if the original pk pathname is rsa_pub.key, then set pk_pathname like this:\n\
                          kmd -P kmc_pub.key\n\
"),
			stdout);

	fputs(
			("\
  -S, --sk_pathname     secret key pathname\033[47;31m[default=kmc_priv.key]\033[0m\n\
                        egg:\n\
                          if the original pk pathname is rsa_pub.key, then set pk_pathname like this:\n\\n\
                          kmd -S kmc_priv.key\n\
"),
			stdout);

	fputs(("\n\
Exit status:\n\
   0  if OK,\n\
  -1  if error\n\
  \n\
"),
			stdout);
	exit(0);
}

void decode_switch(int argc, char **argv, struct kmd_option *x)
{
	int c;
	while (1)
	{
		c = getopt_long_only(argc, argv, "i:p:C:P:S:", long_options, NULL );
		if (c == -1)
			break;

		switch (c)
		{
		case 'i':
			if (*optarg == '=')
				++optarg;
			if (optarg && strlen(optarg) < PATH_MAX)
				strcpy(x->ip, optarg);
			break;

		case 'p':
			if (*optarg == '=')
				++optarg;
			if (optarg && strlen(optarg) < 10)
				x->port = atoi(optarg);
			break;

		case 'c':
			if (*optarg == '=')
				++optarg;
			if (strlen(optarg) < PATH_MAX - 3)
			{
				strcpy(x->config_pathname, optarg);
				strcpy(x->temp_pathname, optarg);
				strcat(x->temp_pathname, ".tm");
			}
			break;

		case 'P':
			if (*optarg == '=')
				++optarg;
			if (strlen(optarg) < PATH_MAX)
				strcpy(x->pk_pathname, optarg);
			break;
		case 'S':
			if (*optarg == '=')
				++optarg;
			if (strlen(optarg) < PATH_MAX)
				strcpy(x->sk_pathname, optarg);
			break;

		case 'h':
			do_help();
			break;

		case 'd':
			x->debug = true;
			if (*optarg == '=')
				++optarg;
			dbg_level = atoi(optarg);
			break;

		case '?':
			exit(-1);

		default:
			printf("?? getopt returned character code 0%o ??\n", c);
			exit(-1);
		}
	}
}

int main(int argc, char **argv)
{
	struct kmd_option *x = (struct kmd_option *) malloc(
			sizeof(struct kmd_option));
	kmd_option_init(x);
	decode_switch(argc, argv, x);

	int sockfd = init_server(x);
	if (sockfd < 0)
	{
		free(x);
		return sockfd;
	}

	FILE * pf = NULL;
	if (NULL == (pf = fopen(pid_pathname, "w")))
	{
		fprintf(stderr, "create %s file error\n", pid_pathname);
		free(x);
		return -1;
	}

	if (!x->debug && daemon(1, 0) < 0)
	{
		fprintf(stderr, "start SA service error\n");
		fclose(pf);
		free(x);
		return -1;
	}

	// record the process pid
	fprintf(pf, "%d", getpid());
	fclose(pf);
	server_work(sockfd, x);

	free(x);
	return 0;
}
