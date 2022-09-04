/*-------------------------------------------------------------------------
 *
 * encryption.h
 *	  Full database encryption support
 *
 *
 * Portions Copyright (c) 2019-2022, CYBERTEC PostgreSQL International GmbH
 * Portions Copyright (c) 1996-2022, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * src/include/storage/encryption.h
 *
 *-------------------------------------------------------------------------
 */
#ifndef ENCRYPTION_H
#define ENCRYPTION_H

#include "access/xlogdefs.h"
#include "common/encryption.h"
#include "miscadmin.h"
#include "storage/block.h"
#include "storage/bufpage.h"
#include "storage/relfilenode.h"
#include "port/pg_crc32c.h"

/* Is the cluster encrypted? */
extern bool data_encrypted;

/*
 * Number of bytes reserved to store encryption sample in ControlFileData.
 */
#define ENCRYPTION_SAMPLE_SIZE 16

typedef int (*read_encryption_key_cb) (void);
/*
 * This function raises ERROR if the cluster is encrypted but the binary does
 * not support encryption, so it's compiled regardless the value of
 * USE_ENCRYPTION. It's less invasive than if we had to ifdef each call.
 */
extern int read_encryption_key(read_encryption_key_cb read_char, int *key_len);

/*
 * Likewise, compile regardless USE_ENCRYPTION.
 */
extern void setup_encryption(void);

#ifndef FRONTEND
/* Copy of the same field of ControlFileData. */
extern char encryption_verification[];

extern XLogRecPtr get_lsn_for_encryption(void);
extern void set_page_lsn_for_encryption(Page page);
extern void set_page_lsn_for_encryption2(Page page1, Page page2);
extern void set_page_lsn_for_encryption3(Page page1, Page page2, Page page3);
#endif	/* FRONTEND */

#define TWEAK_SIZE 16

/*
 * In some cases we need a separate copy of the data because encryption
 * in-place (typically in the shared buffers) would make the data unusable for
 * backends.
 */
extern PGAlignedBlock encrypt_buf;

/*
 * The same for XLOG. This buffer spans multiple pages, in order to reduce the
 * number of syscalls when doing I/O.
 *
 * XXX Fine tune the buffer size.
 */
#define ENCRYPT_BUF_XLOG_SIZE	(XLOG_ENCRYPT_BUF_PAGES * XLOG_BLCKSZ)
extern char *encrypt_buf_xlog;

#define	XLOG_ENCRYPT_BUF_PAGES	8

#ifndef FRONTEND
/*
 * Space for the encryption key in shared memory. Backend that receives the
 * key during startup stores it here so postmaster can eventually take a local
 * copy.
 *
 * Although postmaster should not do anything else with shared memory beyond
 * its setup, mere reading of this structure should not be a problem. The
 * worst thing that shared memory corruption can cause is wrong or missing
 * key, both of which will be detected later during the startup. (Failed
 * startup is not a real crash.) However we don't dare to use spinlock here
 * because that way shared memory corruption could cause postmaster to end up
 * in an infinite loop. See processEncryptionKey() for more comments on
 * synchronization.
 */
typedef struct ShmemEncryptionKey
{
	char	data[ENCRYPTION_KEY_MAX_LENGTH]; /* the key */
	bool	received;				/* received the key message? */
	bool	empty;					/* was the key message empty? */
} ShmemEncryptionKey;

/*
 * Encryption key in the shared memory.
 */
extern ShmemEncryptionKey *encryption_key_shmem;
#endif							/* FRONTEND */

/* Do we have encryption_key and the encryption library initialized? */
extern bool	encryption_setup_done;

#ifndef FRONTEND
extern Size EncryptionShmemSize(void);
extern void EncryptionShmemInit(void);
#endif							/* FRONTEND */

#ifdef USE_ENCRYPTION

extern void encryption_error(bool fatal, char *message);
#endif	/* USE_ENCRYPTION */

/*
 * Different kinds of data require different ciphers and keys.
 */
typedef enum EncryptedDataKind
{
	EDK_REL_WAL,				/* Relations and WAL. */
	EDK_BUFFILE					/* Temporary and transient files
								 * (buffile.c) */
} EncryptedDataKind;

/*
 * These functions do interact with OpenSSL, but we only enclose the relevant
 * parts in "#ifdef USE_ENCRYPTION". Thus caller does not have to use #ifdef
 * and the encryption code is less invasive.
 */
extern void encrypt_block(const char *input, char *output, Size size,
						  char *tweak, XLogRecPtr lsn, BlockNumber block,
						  EncryptedDataKind data_kind);
extern void decrypt_block(const char *input, char *output, Size size,
						  char *tweak, BlockNumber block,
						  EncryptedDataKind data_kind);

/*
 * Convenience macros to encrypt / decrypt relation page.
 */
#define encrypt_page(input, output, lsn, block)			\
	encrypt_block((input), (output), BLCKSZ, NULL, (lsn), (block),		\
				  EDK_REL_WAL);
#define decrypt_page(input, output, block)	\
	decrypt_block((input), (output), BLCKSZ, NULL, (block), \
				  EDK_REL_WAL);

/*
 * The following functions do not interact with OpenSSL directly so they are
 * not ifdef'd using USE_ENCRYPTION. If we ifdef'd them, caller would have to
 * do the same.
 */
extern void sample_encryption(char *buf);
extern void XLogEncryptionTweak(char *tweak, TimeLineID timeline,
					XLogSegNo segment, uint32 offset);
extern void mdtweak(char *tweak, RelFileNode *relnode, ForkNumber forknum,
		BlockNumber blocknum);

#endif							/* ENCRYPTION_H */
