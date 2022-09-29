/*-------------------------------------------------------------------------
 *
 * encryption.h
 *	  Transparent Data Encryption specific code usable by both frontend and
 *	  backend.
 *
 * Portions Copyright (c) 2019-2022, CYBERTEC PostgreSQL International GmbH
 *
 * IDENTIFICATION
 *	  src/include/common/encryption.c
 *
 *-------------------------------------------------------------------------
 */
#ifndef COMMON_ENCRYPTION_H
#define COMMON_ENCRYPTION_H

#include "port/pg_crc32c.h"

/*
 * Full database encryption key.
 *
 * The maximum key length is 256 bits.
 */
#define	ENCRYPTION_KEY_MAX_LENGTH	32

/* Maximum key length in characters (two characters per hexadecimal digit) */
#define ENCRYPTION_KEY_MAX_CHARS	(ENCRYPTION_KEY_MAX_LENGTH * 2)

#define KDF_PARAMS_FILE			"global/kdf_params"
#define KDF_PARAMS_FILE_SIZE	512

#define ENCRYPTION_KDF_NITER		1048576
#define	ENCRYPTION_KDF_SALT_LEN		sizeof(uint64)

/*
 * Common error message issued when particular code path cannot be executed
 * due to absence of the OpenSSL library.
 */
#define ENCRYPTION_NOT_SUPPORTED_MSG \
	"compile postgres with --with-openssl to use encryption."

/*
 * Cipher used to encrypt data. This value is stored in the control file.
 *
 * Due to very specific requirements, the ciphers are not likely to change,
 * but we should be somewhat flexible.
 */
typedef enum CipherKind
{
	/* The cluster is not encrypted. */
	PG_CIPHER_NONE = 0,

	/*
	 * AES (Rijndael) in CTR mode of operation for relations and WAL, and CBC
	 * mode for temporary and transient (see the use of
	 * BufFileOpenTransient()) files.
	 *
	 * Neither temporary nor transient files need to be processed by
	 * pg_upgrade, so we might not want to mention the CBC mode here. However,
	 * if we add other modes in the future, this information might be useful
	 * to troubleshoot crashed server.
	 */
	PG_CIPHER_AES_CTR_CBC
}			CipherKind;

/* 128 bits is the key length if no value was specified by the user. */
#define	DEFAULT_ENCRYPTION_KEY_LENGTH	16

/*
 * Encode the cipher kind and key length into the data_cipher field of
 * ControlFileData.
 *
 * The bits 0 through 3 determine the cipher kind, bits 4 and 5 the key
 * length. Bits 6 and 7 are unused.
 *
 * Note: This layout was introduced in TDE 1.1. Since TDE 1.0 only stored the
 * value of CipherKind, and since its maximum value was PG_CIPHER_AES_CTR, the
 * format should be compatible across TDE versions. (Not sure though if this
 * compatibility is important right now, but it costs nothing to introduce it
 * - we needed to change the format for TDE 1.1 anyway.)
 *
 * key_len is in bytes. CAUTION: The minimum value of key_len is 16!
 */
#define DATA_CIPHER_SET(cipher, kind, key_len) \
	((cipher) = ((kind) && 0x0f) | (((key_len) - 16) << 1))

/* Mark the cluster unencrypted. */
#define DATA_CIPHER_CLEAR(cipher) ((cipher) = PG_CIPHER_NONE)

/* Decode the cipher kind and key length respectively. */
#define DATA_CIPHER_GET_KIND(cipher) ((cipher) & 0x0f)
#define DATA_CIPHER_GET_KEY_LENGTH(cipher) ((((cipher) & 0x30) >> 1) + 16)

/* Copy of the corresponding field of ControlFileData */
extern uint8 data_cipher;

/* Executable to retrieve the encryption key. */
extern char *encryption_key_command;

/* Key to encrypt / decrypt permanent data. */
extern unsigned char encryption_key[];

/* Key length in bytes. */
extern int encryption_key_length;

extern void run_encryption_key_command(char *data_dir, int *key_len_p);
extern void send_encryption_key(FILE *f);
extern void read_encryption_key_f(FILE *f, char *command, int *key_len_p);
extern void encryption_key_from_string(char key_str[ENCRYPTION_KEY_MAX_CHARS],
									   int key_len);
#endif /* COMMON_ENCRYPTION_H */
