/*
 * config.h
 *
 *  Created on: 2014-8-19
 *      Author: pc
 */

#ifndef CONFIG_H_
#define CONFIG_H_

#include <sys/file.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <stdbool.h>
#include <limits.h>
#include "encrypt.h"

char *get_column(char *line, int col);

bool is_valid_column(const char *line, size_t len, const char *priv);

int do_getline(const char *pathname,
		int (*proc_line)(const char *line, size_t len, const void *priv,
				const void *en), const void *priv, const void *en);

int do_putline(const char *pathname, const char *temp_pathname,
		int (*proc_line)(const char *line, char *result, size_t len,
				const char *id, const char *uuid), const char *id,
		const char *uuid);

int get_uuid_number(const char *line);

int print_line(const char *line, size_t len, const void *priv, const void *en);

int print_id_uuid(const char *line, size_t len, const void *priv,
		const void *en);

int print_id(const char *line, size_t len, const void *priv, const void *en);

int print_key(const char *line, size_t len, const void *priv,
		const struct encrypt_operations *en);

int print_uuid(const char *line, size_t len, const void *priv, const void *en);

int remove_uuid(const char *line, char *result, size_t len, const char *id,
		const char *uuid);

int add_uuid(const char *line, char *result, size_t len, const char *id,
		const char *uuid);

int remove_id(const char *line, char *result, size_t len, const char *id,
		const char *uuid);

int update_uuid(const char *line, char *result, size_t len, const char *id,
		const char *uuid);

int do_list_line(const char *pathname);

int do_list_id(const char *pathname, const char *priv);

int do_list_key(const char *pathname, const char *priv,
		struct encrypt_operations *en);

int do_list_uuid(const char *pathname, const char *priv);

int do_list_id_uuid(const char *pathname, const char *priv);

int do_remove_uuid(const char *pathname, const char *temp_pathname,
		const char *uuid);

int do_remove_id(const char *pathname, const char *temp_pathname,
		const char *id);

int do_update_uuid(const char *pathname, const char *temp_pathname,
		const char *id, const char *uuid);

#endif /* CONFIG_H_ */
