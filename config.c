/*
 * config.c
 *
 *  Created on: 2014-8-19
 *      Author: wzb
 *
 */
#include "config.h"

#define UUID_MAX_NUM  10
#define string_space " \n\t\f\r\v"
char *get_column(char *line, int col)
{
	char *ptr = NULL;
	ptr = strtok(line, string_space);
	col--;

	while (ptr && col--)
		ptr = strtok(NULL, string_space);

	return ptr;
}

/**
 * judge if the priv is the valid column of line
 */bool is_valid_column(const char *line, size_t len, const char *priv)
{
	char *ptr = NULL;
	ptr = strstr(line, priv);
	while (ptr)
	{
		if (strlen(ptr) != strlen(line)
				&& !(isspace(*(ptr-1)) || ',' == *(ptr - 1)))
			ptr = strstr(ptr + strlen(priv), priv);
		else if (strlen(ptr) == strlen(priv) || isspace(ptr[strlen(priv)])
				|| ',' == ptr[strlen(priv)])
			return true;
		else
			ptr = strstr(ptr + strlen(priv), priv);
	}
	return false;
}

int do_getline(const char *pathname,
		int (*proc_line)(const char *line, size_t len, const void *priv,
				const void *en), const void *priv, const void *en)
{
	size_t n;
	int ret = 0;
	char line[LINE_MAX];

	FILE *f = fopen(pathname, "r");

	if (NULL == f)
	{
		fprintf(stderr, "could not open conf %s\n", pathname);
		return -ENOENT;
	}

	if (0 != flock(fileno(f), LOCK_SH | LOCK_NB))
	{
		// if file locked, then exit
		fprintf(stderr, "%s used, try later\n", pathname);
		exit(-1);
	}

	while (fgets(line, LINE_MAX, f))
	{
		char *beg = line;

		while (*beg && isspace(*beg))
			beg++;
		if (*beg == '#' || *beg == '\0')
			continue;

		n = strlen(beg);
		while (n && (line[n - 1] == '\r' || line[n - 1] == '\n'))
			--n;
		if (!n)
			continue;

		ret = proc_line(beg, n, priv, en);
		if (ret)
			break;
	}

	flock(fileno(f), LOCK_UN);
	fclose(f);
	return ret;
}

int do_putline(const char *pathname, const char *temp_pathname,
		int (*proc_line)(const char *line, char *result, size_t len,
				const char *id, const char *uuid), const char *id,
		const char *uuid)
{
	char line[LINE_MAX];

	FILE *f = fopen(pathname, "r");
	FILE *f2 = fopen(temp_pathname, "w");

	if (NULL == f || NULL == f2)
	{
		fprintf(stderr, "could not open conf %s\n", pathname);
		return -ENOENT;
	}

	if (0 != flock(fileno(f), LOCK_EX | LOCK_NB))
	{
		// if file locked, then exit
		fprintf(stderr, "%s used, try later\n", pathname);
		return -1;
	}

	while (fgets(line, LINE_MAX, f))
	{
		char beg[LINE_MAX];
		int i = 0;
		int line_len = strlen(line);
		while (i < line_len && isspace(line[i]))
			++i;
		if (i == line_len || line[i] == '#')
		{
			fputs(line, f2);
			continue;
		}

		if (proc_line(line, beg, LINE_MAX, id, uuid))
			fputs(beg, f2);
		else
			fputs(line, f2);
	}

	flock(fileno(f), LOCK_UN);
	fclose(f);
	fclose(f2);
	rename(temp_pathname, pathname);
	return 0;
}

#define COL_ID		1
#define COL_KEY		2
#define COL_UUID	3
int get_uuid_number(const char *line)
{
	char *ptr = NULL;
	int num = 0;

	char temp[LINE_MAX];
	strcpy(temp, line);
	ptr = get_column(temp, COL_UUID);
	if (NULL == ptr)
		return 0;

	ptr = strtok(ptr, ","); //split uuid
	while (ptr)
	{
		num++;
		ptr = strtok(NULL, ",");
	}
	return num;
}

int print_line(const char *line, size_t len, const void *priv, const void *en)
{
	char temp[LINE_MAX];
	strcpy(temp, line);
	printf("%s ", get_column(temp, COL_ID));
	strcpy(temp, line);
	const char *uuid = get_column(temp, COL_UUID);
	if (uuid)
		printf("%s\n", uuid);
	else
		printf("\n");
	return 0;
}

int print_id_uuid(const char *line, size_t len, const void *priv,
		const void *en)
{
	if (!is_valid_column(line, len, (const char *) priv))
		return 0;

	print_line(line, len, priv, en);
	return 1;
}

int print_id(const char *line, size_t len, const void *priv, const void *en)
{
	if (!is_valid_column(line, len, (const char *) priv))
		return 0;

	char temp[LINE_MAX];
	strcpy(temp, line);
	printf("%s\n", get_column(temp, COL_ID));
	return 1;
}

int print_key(const char *line, size_t len, const void *priv,
		const struct encrypt_operations *en)
{
	if (!is_valid_column(line, len, priv))
		return 0;

	char temp[LINE_MAX];
	strcpy(temp, line);
	const char *key = NULL;
	char result[200];
	if (!en || !(key = get_column(temp, COL_KEY))
			|| !((*(en->decrypt))(key, result, 200, en->sk_filename)))
	{
		fprintf(stderr, "fail to decrypt the volume key\n");
		return -1;
	}

	/*
	 * if vk is binary format and based before being encrypted
	 * 		you should debase it first, and print the hexadecimal format
	 */
	char volume_key[50];
	debase64(result, strlen(result), volume_key, 50);
	int i = 0;
	while (i < strlen(volume_key))
		printf("%02x", (unsigned char) volume_key[i++]);
	printf("\n");

	printf("%s\n", result);
	return 1;
}

int print_uuid(const char *line, size_t len, const void *priv, const void *ptr)
{
	if (!is_valid_column(line, len, (const char *) priv))
		return 0;

	char temp[LINE_MAX];
	strcpy(temp, line);
	const char *uuid = get_column(temp, COL_UUID);
	if (uuid)
		printf("%s\n", uuid);
	else
		printf("\n");
	return 1;
}

int remove_uuid(const char *line, char *result, size_t len, const char *id,
		const char *uuid)
{
	char *ptr = strstr(line, uuid);
	int length = 0;
	int tag = 0;
	if (ptr == NULL )
		return 0;

	int i = 0;
	while (i < strlen(line))
	{
		result[i++] = 0;
	}

	length = ptr - line;
	if (line[length - 1] == ',')
	{
		tag = 1;
		length -= 1;
	}

	strncpy(result, line, length);
	if (ptr[strlen(uuid)] == ',' && tag == 0) // only remove one ','
		ptr++;
	strcat(result, ptr + strlen(uuid));
	return 1;
}

int add_uuid(const char *line, char *result, size_t len, const char *id,
		const char *uuid)
{
	int line_len = strlen(line);
	if (!is_valid_column(line, line_len, id) || line_len + strlen(uuid) >= len)
	{
		return 0;
	}

	int num = get_uuid_number(line);
	if (num > UUID_MAX_NUM)
	{
		fprintf(stderr,
				"%s number overflow, please selected another volume key\n", id);
		return -1;
	}

	while (line[line_len - 1] == '\r' || line[line_len - 1] == '\n')
		line_len--;
	strncpy(result, line, line_len);
	if (strlen(result) > line_len)
		result[line_len] = '\0';
	if (num > 0)
		strcat(result, ",");
	else if (!isspace(line[line_len- 1]))
		strcat(result, " ");
	strcat(result, uuid);
	strcat(result, "\n");
	return 1;
}

int remove_id(const char *line, char *result, size_t len, const char *id,
		const char *uuid)
{
	if (is_valid_column(line, strlen(line), id))
	{
		strcpy(result, "");
		return 1;
	}
	else
		return 0;
}

int update_uuid(const char *line, char *result, size_t len, const char *id,
		const char *uuid)
{
	if (remove_uuid(line, result, len, NULL, uuid))
		return 1;

	return add_uuid(line, result, len, id, uuid);
}

int do_list_line(const char *pathname)
{
	return do_getline(pathname, print_line, NULL, NULL );
}

int do_list_id(const char *pathname, const char *priv)
{
	return do_getline(pathname, print_id, priv, NULL );
}

int do_list_key(const char *pathname, const char *priv,
		struct encrypt_operations *en)
{
	return do_getline(pathname, print_key, priv, en);
}

int do_list_uuid(const char *pathname, const char *priv)
{
	return do_getline(pathname, print_uuid, priv, NULL );
}

int do_list_id_uuid(const char *pathname, const char *priv)
{
	return do_getline(pathname, print_id_uuid, priv, NULL );
}

int do_remove_uuid(const char *pathname, const char *temp_pathname,
		const char *uuid)
{
	return do_putline(pathname, temp_pathname, remove_uuid, NULL, uuid);
}

int do_remove_id(const char *pathname, const char *temp_pathname,
		const char *id)
{
	return do_putline(pathname, temp_pathname, remove_id, id, NULL );
}

int do_update_uuid(const char *pathname, const char *temp_pathname,
		const char *id, const char *uuid)
{
	if (do_getline(pathname, is_valid_column, id, NULL ))
		return do_putline(pathname, temp_pathname, update_uuid, id, uuid);

	fprintf(stderr, "%s invalid volume id\n", id);
	exit(0);
}
