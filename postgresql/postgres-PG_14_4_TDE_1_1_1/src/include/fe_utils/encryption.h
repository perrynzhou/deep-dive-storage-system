/*-------------------------------------------------------------------------
 *
 * encryption.h
 *	  Client code to support full cluster encryption.
 *
 * Portions Copyright (c) 2019-2022, CYBERTEC PostgreSQL International GmbH
 * Portions Copyright (c) 1996-2022, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * IDENTIFICATION
 *	  src/include/fe_utils/encryption.h
 *
 *-------------------------------------------------------------------------
 */
#include "common/encryption.h"

extern void init_kdf(int key_len);
extern void update_kdf_key_length(uint8 key_len);
extern void write_kdf_file(char *dir);
extern int read_kdf_file(char *dir);
extern void derive_key_from_password(unsigned char *encryption_key,
									 const char *password, int len);

/*
 * Arguments for send_key_to_postmaster().
 *
 * If host or port are NULL, we expect libpq to use its defaults.
 *
 * If encryption_key is NULL, send an "empty message". This tells postmaster
 * that the client (typically pg_ctl) has no key, so postmaster should stop
 * waiting for it and try to get the key elsewhere.
 *
 * If error occurs, the appropriate message is stored in error_msg.
 */
typedef struct SendKeyArgs
{
	char	*host;
	char	*port;
	const unsigned char *encryption_key;

	long pm_pid;
	bool	pm_exited;
#ifdef WIN32
	/*
	 * Set this *in addition to* pm_pid, otherwise it's hard to tell whether
	 * the handle is valid.
	 */
	HANDLE	pmProcess;
#endif

	char *error_msg;
} SendKeyArgs;

extern bool send_key_to_postmaster(SendKeyArgs *args);
