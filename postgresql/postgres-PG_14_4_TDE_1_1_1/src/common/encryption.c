/*-------------------------------------------------------------------------
 *
 * encryption.c
 *	  Transparent Data Encryption specific code usable by both frontend and
 *	  backend.
 *
 * Portions Copyright (c) 2019-2021, CYBERTEC PostgreSQL International GmbH
 *
 * IDENTIFICATION
 *	  src/common/encryption.c
 *
 *-------------------------------------------------------------------------
 */
#ifndef FRONTEND
#include "postgres.h"
#else
#include "postgres_fe.h"
#endif

#include "common/encryption.h"
#include "common/logging.h"

#ifdef USE_ENCRYPTION
#include <openssl/evp.h>
#endif	/* USE_ENCRYPTION */

unsigned char encryption_key[ENCRYPTION_KEY_MAX_LENGTH];
int	encryption_key_length = 0;

/* Copy of the corresponding field of ControlFileData */
uint8 data_cipher = 0;

char	   *encryption_key_command = NULL;

/*
 * Run the command that is supposed to generate encryption key and store it
 * where encryption_key points to. If valid string is passed for data_dir,
 * it's used to replace '%D' pattern in the command.
 *
 * If *key_len_p is greater than zero, it specifies the expected key
 * length. If it's zero, caller expects the actual length to be reported via
 * this argument.
 */
void
run_encryption_key_command(char *data_dir, int *key_len_p)
{
	FILE	   *fp;
	int		dlen;
	char	*cmd, *sp, *dp, *endp;

	Assert(encryption_key_command != NULL &&
		   strlen(encryption_key_command) > 0);

	dlen = strlen(encryption_key_command);
	if (data_dir)
		dlen += strlen(data_dir);
	/*
	 * The terminating '\0'. XXX Is it worth subtracting 2 for the "%D"
	 * part?
	 */
	dlen += 1;
	cmd = palloc(dlen);

	/*
	 * Replace %D pattern in the command with the actual data directory path.
	 */
	dp = cmd;
	endp = cmd + dlen - 1;
	*endp = '\0';
	for (sp = encryption_key_command; *sp; sp++)
	{
		if (*sp == '%')
		{
			if (sp[1] == 'D')
			{
				if (data_dir == NULL)
				{
#ifdef FRONTEND
					pg_log_fatal("data directory is not known, %%D pattern cannot be replaced");
					exit(EXIT_FAILURE);
#else
					ereport(FATAL,
							(errmsg("data directory is not known, %%D pattern cannot be replaced")));
#endif	/* FRONTEND */
				}

				sp++;
				strlcpy(dp, data_dir, endp - dp);
				make_native_path(dp);
				dp += strlen(dp);
			}
			else if (dp < endp)
				*dp++ = *sp;
			else
				break;
		}
		else
		{
			if (dp < endp)
				*dp++ = *sp;
			else
				break;
		}
	}
	*dp = '\0';

	/* Do not print the command itself, in case it's just "echo <the key>" */
#ifdef FRONTEND
	pg_log_debug("executing encryption key command");
#else
	ereport(DEBUG1,
			(errmsg("executing encryption key command")));
#endif	/* FRONTEND */

	fp = popen(cmd, "r");
	if (fp == NULL)
	{
#ifdef FRONTEND
		pg_log_fatal("could not execute \"%s\"", cmd);
		exit(EXIT_FAILURE);
#else
		ereport(FATAL,
				(errmsg("could not execute \"%s\"", cmd)));
#endif	/* FRONTEND */
	}

	/* Read the key. */
	read_encryption_key_f(fp, cmd, key_len_p);

	if (pclose(fp) != 0)
	{
#ifdef FRONTEND
		pg_log_fatal("could not close pipe to \"%s\"", cmd);
		exit(EXIT_FAILURE);
#else
		ereport(FATAL,
				(errmsg("could not close pipe to \"%s\"", cmd)));
#endif	/* FRONTEND */
	}
	pfree(cmd);
}

/*
 * Send encryption key in hexadecimal format to the file stream passed.
 *
 * The backend processes could actually receive binary data but that would
 * make startup of postgres in single-user mode less convenient.
 */
void
send_encryption_key(FILE *f)
{
	int	i;

	for (i = 0; i < encryption_key_length; i++)
		fprintf(f, "%.2x", encryption_key[i]);
	fputc('\n', f);
}



/*
 * Read the encryption key from a file stream.
 *
 * The header comment of run_encryption_key_command() explains the key_len_p
 * argument.
 */
void
read_encryption_key_f(FILE *f, char *command, int *key_len_p)
{
	char	   buf[ENCRYPTION_KEY_MAX_CHARS];
	int		key_len = *key_len_p;
	int		read_len, c;
	int		key_chars = key_len * 2;

	Assert(key_len == 0 || key_len == 16 || key_len == 24 || key_len == 32);

	read_len = 0;
	while ((c = fgetc(f)) != EOF && c != '\n')
	{
		if (read_len >= ENCRYPTION_KEY_MAX_CHARS)
		{
#ifdef FRONTEND
			pg_log_fatal("encryption key is too long, should contain no more than %d hexadecimal characters",
						 ENCRYPTION_KEY_MAX_CHARS);
			exit(EXIT_FAILURE);
#else
			ereport(FATAL,
					(errmsg("encryption key is too long, should contain no more than %d hexadecimal characters",
							ENCRYPTION_KEY_MAX_CHARS)));
#endif	/* FRONTEND */
		}

		if (key_len > 0 && read_len >= key_chars)
		{
#ifdef FRONTEND
			pg_log_fatal("encryption key is too long, should be a %d character hex string",
						 key_len * 2);
			exit(EXIT_FAILURE);
#else
			ereport(FATAL,
					(errmsg("encryption key is too long, should be a %d character hex string",
						key_len * 2)));
#endif	/* FRONTEND */
		}

		buf[read_len++] = c;
	}

	if (c == EOF && read_len == 0)
	{
		char	src[MAXPGPATH];

		if (command)
			snprintf(src, MAXPGPATH, "command \"%s\"", command);
		else
			snprintf(src, MAXPGPATH, "stdin");

#ifdef FRONTEND
		pg_log_fatal("could not read encryption key from %s", src);
		exit(EXIT_FAILURE);
#else
		ereport(FATAL,
				(errmsg("could not read encryption key from %s",
						src)));
#endif	/* FRONTEND */
	}

	if (key_chars > 0 && read_len < key_chars)
	{
#ifdef FRONTEND
		pg_log_fatal("encryption key is too short, should be a %d character hex string",
					 key_len * 2);
		exit(EXIT_FAILURE);
#else
		ereport(FATAL,
				(errmsg("encryption key is too short, should be a %d character hex string",
					key_len * 2)));
#endif	/* FRONTEND */
	}

	Assert(read_len % 2 == 0);
	if (key_len == 0)
	{
		key_len = read_len / 2;
		*key_len_p = key_len;
	}

	/* Turn the hexadecimal representation into an array of bytes. */
	encryption_key_from_string(buf, key_len);
}

/*
 * Use the input hexadecimal string to initialize the encryption_key variable.
 */
void
encryption_key_from_string(char key_str[ENCRYPTION_KEY_MAX_CHARS], int key_len)
{
	int	encr_key_int[ENCRYPTION_KEY_MAX_LENGTH];
	int	i;

	for (i = 0; i < key_len; i++)
	{
		/*
		 * The code would be simpler with %2hhx conversion, but it does not
		 * seem to be well portable. At least mingw build on Windows
		 * complains about it.
		 */
		if (sscanf(key_str + 2 * i, "%2x", encr_key_int + i) == 0)
		{
#ifdef FRONTEND
			pg_log_fatal("the encryption key may only contain hexadecimal digits");
			exit(EXIT_FAILURE);
#else
			ereport(FATAL,
					(errmsg("the encryption key may only contain hexadecimal digits")));
#endif	/* FRONTEND */
		}
	}
	memset(encryption_key, 0, ENCRYPTION_KEY_MAX_LENGTH);
	for (i = 0; i < key_len; i++)
		encryption_key[i] = (char) encr_key_int[i];
}
