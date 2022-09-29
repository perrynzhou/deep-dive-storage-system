/*-------------------------------------------------------------------------
 *
 * encryption.c
 *	  This code handles encryption and decryption of data.
 *
 * Portions Copyright (c) 2019-2022, CYBERTEC PostgreSQL International GmbH
 *
 * See src/backend/storage/file/README.encryption for explanation of the
 * design.
 *
 * IDENTIFICATION
 *	  src/backend/storage/file/encryption.c
 *
 * NOTES
 *		This file is compiled as both front-end and backend code, so the
 *		FRONTEND macro must be used to distinguish the case if we need to
 *		report error or if server-defined variable / function seems useful.
 *
 *-------------------------------------------------------------------------
 */

#include "postgres.h"
#include "fmgr.h"

#include <sys/stat.h>

#include "access/xlog.h"
#include "access/xlogdefs.h"
#include "common/fe_memutils.h"
#include "common/sha2.h"
#include "common/string.h"
#include "catalog/pg_class.h"
#include "catalog/pg_control.h"
#include "storage/bufpage.h"
#include "storage/encryption.h"
#include "utils/fmgrprotos.h"

#ifndef FRONTEND
#include "port.h"
#include "storage/shmem.h"
#include "storage/fd.h"
#include "utils/memutils.h"
#endif							/* FRONTEND */

#ifdef USE_ENCRYPTION
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/opensslv.h>

EVP_CIPHER_CTX *ctx_encrypt, *ctx_decrypt,
	*ctx_encrypt_buffile, *ctx_decrypt_buffile;
#endif							/* USE_ENCRYPTION */

#ifndef FRONTEND
ShmemEncryptionKey *encryption_key_shmem = NULL;
#endif							/* FRONTEND */

bool		data_encrypted = false;

char encryption_verification[ENCRYPTION_SAMPLE_SIZE];

bool	encryption_setup_done = false;

PGAlignedBlock encrypt_buf;
char	   *encrypt_buf_xlog = NULL;

#ifdef USE_ENCRYPTION
static void init_encryption_context(EVP_CIPHER_CTX **ctx_p, bool encrypt,
									bool buffile);
static void evp_error(void);
#endif	/* USE_ENCRYPTION */

#ifndef FRONTEND
/*
 * Report space needed for our shared memory area
 */
Size
EncryptionShmemSize(void)
{
	return sizeof(ShmemEncryptionKey);
}

/*
 * Initialize our shared memory area
 */
void
EncryptionShmemInit(void)
{
	bool	found;

	encryption_key_shmem = ShmemInitStruct("Cluster Encryption Key",
										   EncryptionShmemSize(),
										   &found);
	if (!IsUnderPostmaster)
	{
		Assert(!found);

		encryption_key_shmem->received = false;
		encryption_key_shmem->empty = false;
	}
	else
		Assert(found);
}

/*
 * Read encryption key in hexadecimal form from stdin and store it in
 * encryption_key variable.
 *
 * key_len can be used to pass the expected key length. Pass NULL if the
 * information is not available.
 *
 * Returns the key length actually seen.
 */
int
read_encryption_key(read_encryption_key_cb read_char, int *key_len)
{
#ifdef USE_ENCRYPTION
	char	buf[ENCRYPTION_KEY_MAX_CHARS];
	int		read_len, c;
	int		key_chars;
	int		actual_key_len;

	if (key_len)
		key_chars = *key_len * 2; /* 2 hexadecimal characters per byte */
	else
		key_chars = ENCRYPTION_KEY_MAX_CHARS;

	read_len = 0;
	while ((c = (*read_char)()) != EOF && c != '\n')
	{
		if (read_len >= key_chars)
		{
			if (key_len)
				ereport(FATAL,
						(errmsg("encryption key is too long, should be a %d character hex string",
								key_chars)));
			else
				ereport(FATAL,
						(errmsg("encryption key is too long")));
		}

		buf[read_len++] = c;
	}

	/*
	 * Cannot check if the key is too short if the expected length is not
	 * known.
	 */
	if (key_len && read_len < key_chars)
		ereport(FATAL,
				(errmsg("encryption key is too short, should be a %d character hex string",
						key_chars)));

	key_chars = read_len;
	actual_key_len = key_chars / 2;

	/* Turn the hexadecimal representation into an array of bytes. */
	encryption_key_from_string(buf, actual_key_len);

	return actual_key_len;

#else  /* !USE_ENCRYPTION */
	/*
	 * If no encryption implementation is linked and caller requests
	 * encryption, we should error out here and thus cause the calling process
	 * to fail (preferably postmaster, so the child processes don't make the
	 * same mistake).
	 */
	ereport(FATAL, (errmsg(ENCRYPTION_NOT_SUPPORTED_MSG)));
#endif	/* USE_ENCRYPTION */
}
#endif							/* !FRONTEND */


/*
 * Initialize encryption subsystem for use. Must be called before any
 * encryptable data is read from or written to data directory.
 */
void
setup_encryption(void)
{
#ifdef USE_ENCRYPTION
	/*
	 * Setup OpenSSL.
	 *
	 * None of these functions should return a value or raise error.
	 */
	ERR_load_crypto_strings();
	OpenSSL_add_all_algorithms();

#if OPENSSL_VERSION_NUMBER < 0x10100000L
	OPENSSL_config(NULL);
#endif

	/* Currently we only use this one cipher. */
	Assert(DATA_CIPHER_GET_KIND(data_cipher) == PG_CIPHER_AES_CTR_CBC);

	init_encryption_context(&ctx_encrypt, true, false);
	init_encryption_context(&ctx_decrypt, false, false);
	init_encryption_context(&ctx_encrypt_buffile, true, true);
	init_encryption_context(&ctx_decrypt_buffile, false, true);

	/*
	 * We need multiple pages here, so allocate the memory dynamically instead
	 * of using PGAlignedBlock. That also ensures it'll be MAXALIGNed, which
	 * is useful because the buffer will be used for I/O.
	 *
	 * Use TopMemoryContext because on server side this code is run by
	 * postmaster and postmaster context gets freed after fork().
	 */
#ifndef FRONTEND
	encrypt_buf_xlog = (char *) MemoryContextAlloc(TopMemoryContext,
												   ENCRYPT_BUF_XLOG_SIZE);
#else
	encrypt_buf_xlog = (char *) palloc(ENCRYPT_BUF_XLOG_SIZE);
#endif

	encryption_setup_done = true;
#else  /* !USE_ENCRYPTION */
#ifndef FRONTEND
	/*
	 * If no encryption implementation is linked and caller requests
	 * encryption, we should error out here and thus cause the calling process
	 * to fail (preferably postmaster, so the child processes don't make the
	 * same mistake).
	 */
	ereport(FATAL, (errmsg(ENCRYPTION_NOT_SUPPORTED_MSG)));
#else
	/* Front-end shouldn't actually get here, but be careful. */
	fprintf(stderr, "%s\n", ENCRYPTION_NOT_SUPPORTED_MSG);
	exit(EXIT_FAILURE);
#endif	/* FRONTEND */
#endif							/* USE_ENCRYPTION */
}

/*
 * Encrypts a fixed value into *buf to verify that encryption key is correct.
 * Caller provided buf needs to be able to hold at least ENCRYPTION_SAMPLE_SIZE
 * bytes.
 */
void
sample_encryption(char *buf)
{
	char		tweak[TWEAK_SIZE];
	int			i;

	for (i = 0; i < TWEAK_SIZE; i++)
		tweak[i] = i;

	encrypt_block("postgresqlcrypt", buf, ENCRYPTION_SAMPLE_SIZE, tweak,
				  InvalidXLogRecPtr, InvalidBlockNumber, EDK_REL_WAL);
}

/*
 * Encrypts one block of data with a specified tweak value. May only be called
 * when encryption_enabled is true.
 *
 * Input and output buffer may point to the same location.
 *
 * "size" must be a (non-zero) multiple of ENCRYPTION_BLOCK.
 *
 * "tweak" value must be an array of at least TWEAK_SIZE bytes. If NULL is
 * passed, we suppose that the input data starts with PageHeaderData. In this
 * case page LSN is not encrypted because we use it as an encryption
 * initialization vector (IV), and will need that for decryption. Therefore,
 * if tweak==NULL, valid LSN must be passed. In such a case, page checksum
 * stays unencrypted too because it should be computed later out of the
 * encrypted data (the encrypted data is what we actually store to disk).
 *
 * "block" is number of relation block to be added to the tweak if we
 * construct it here. Ignored if a valid tweak is passed.
 *
 * All-zero blocks are not encrypted to correctly handle relation extension,
 * and also to simplify handling of holes created by seek past EOF and
 * consequent write (see buffile.c). And specifically for relation pages, the
 * problem is that empty page does not have valid LSN.
 */
void
encrypt_block(const char *input, char *output, Size size, char *tweak,
			  XLogRecPtr lsn, BlockNumber block,
			  EncryptedDataKind data_kind)
{
#ifdef USE_ENCRYPTION
	EVP_CIPHER_CTX *ctx;
	int			out_size;
	char	tweak_loc[TWEAK_SIZE];

	Assert(data_encrypted);

	/*
	 * If caller passed no tweak, we assume this is relation page and LSN
	 * should be used.
	 */
	if (tweak == NULL)
	{
		size_t	unencr_size;
		char	*c = tweak_loc;

		Assert(block != InvalidBlockNumber);
		Assert(!XLogRecPtrIsInvalid(lsn));

		memset(c, 0, TWEAK_SIZE);

		/*
		 * The CTR mode counter is big endian (see crypto/modes/ctr128.c in
		 * OpenSSL) and the lower part is used by OpenSSL internally.
		 * Initialize the upper 12 bytes (8 for LSN + 4 for the block number)
		 * and leave the lower eight to OpenSSL - as the counter is increased
		 * once per 16 bytes of input, and as we hardly ever encrypt more than
		 * BLCKSZ bytes at a time, it's not possible for the lower part to
		 * overflow into the upper one: the maximum value of BLCKSZ is 2^15
		 * and the encryption block takes 2^4 bytes, so the counter should not
		 * exceed 2^11. Thus the counter needs no more than 11 bits.
		 *
		 * Note that we copy the lsn from the argument, not from the input
		 * buffer. Since "input" can be a shared buffer locked only in shared
		 * mode, MarkBufferDirtyHint() can update the LSN while we're copying
		 * it. Thus the LSN we use in the tweak could be different from the
		 * one we write to "output" below, and it would be impossible to
		 * decrypt the page.
		 */
		PageSetLSN(c, lsn);
		c += sizeof(PageXLogRecPtr);

		/*
		 * Add the block number, in case a single WAL record affects two (or
		 * more?) pages. Likewise, different endian-ness of the block number
		 * does not affect its uniqueness.
		 */
		memcpy(c, &block, sizeof(BlockNumber));

		tweak = tweak_loc;

		/*
		 * Copy the LSN to the output. Again, use the argument, not the
		 * input buffer.
		 */
		if (input != output)
			PageSetLSN(output, lsn);

		/* Do not encrypt the LSN and checksum. */
		unencr_size = offsetof(PageHeaderData, pd_flags);
		input += unencr_size;
		output += unencr_size;
		size -= unencr_size;
	}
	/*
	 * Empty page is not worth encryption, and encryption of zeroes wouldn't
	 * even be secure.
	 */
	else if (IsAllZero(input, size))
	{
		if (input != output)
			memset(output, 0, size);
		return;
	}

	ctx = data_kind != EDK_BUFFILE ? ctx_encrypt : ctx_encrypt_buffile;

	/*
	 * The amount of encrypted data should be a multiple of the encryption
	 * block size.
	 */
#ifdef USE_ASSERT_CHECKING
	if (EVP_CIPHER_CTX_block_size(ctx) > 1)
		Assert(size % EVP_CIPHER_CTX_block_size(ctx) == 0);
#endif

	/* For the AES-CBC mode make sure the IV is unpredictable. */
	if (data_kind == EDK_BUFFILE)
	{
		char	tweak_iv[TWEAK_SIZE];

		memset(tweak_iv, 0, TWEAK_SIZE);

		if (EVP_EncryptInit_ex(ctx, NULL, NULL, encryption_key,
							   (unsigned char *) tweak_iv) != 1)
			evp_error();

		if (EVP_EncryptUpdate(ctx, (unsigned char *) tweak,
							  &out_size, (unsigned char *) tweak,
							  TWEAK_SIZE) != 1)
			evp_error();

		if (out_size != TWEAK_SIZE)
		{
#ifndef FRONTEND
			ereport(ERROR, (errmsg("Some data left undecrypted")));
#else
			/* Front-end shouldn't actually get here, but be careful. */
			fprintf(stderr, "Some data left undecrypted\n");
			exit(EXIT_FAILURE);
#endif	/* FRONTEND */
		}

		/* Initialize again, using the encrypted IV. */
		if (EVP_EncryptInit_ex(ctx, NULL, NULL, encryption_key,
							   (unsigned char *) tweak) != 1)
			evp_error();
	}
	else
		if (EVP_EncryptInit_ex(ctx, NULL, NULL, encryption_key,
							   (unsigned char *) tweak) != 1)
			evp_error();

	/* Do the actual encryption. */
	if (EVP_EncryptUpdate(ctx, (unsigned char *) output,
						  &out_size, (unsigned char *) input, size) != 1)
		evp_error();

	/*
	 * The EVP documentation seems to allow that not all data is encrypted
	 * at the same time, but the low level code does encrypt everything.
	 */
	if (out_size != size)
	{
#ifndef FRONTEND
		ereport(ERROR, (errmsg("Some data left unencrypted")));
#else
		/* Front-end shouldn't actually get here, but be careful. */
		fprintf(stderr, "Some data left unencrypted\n");
		exit(EXIT_FAILURE);
#endif	/* FRONTEND */
	}
#else  /* !USE_ENCRYPTION */
	/* data_encrypted should not be set */
	Assert(false);
#endif							/* USE_ENCRYPTION */
}

/*
 * Decrypts one block of data with a specified tweak value. May only be called
 * when encryption_enabled is true.
 *
 * Input and output buffer may point to the same location.
 *
 * For detailed comments see encrypt_block().
 *
 * Unlike encrypt_block(), we don't expect page LSN to change during
 * decryption, so we can read it from the input buffer.
 */
void
decrypt_block(const char *input, char *output, Size size, char *tweak,
			  BlockNumber block, EncryptedDataKind data_kind)
{
#ifdef USE_ENCRYPTION
	EVP_CIPHER_CTX *ctx;
	int			out_size;
	char	tweak_loc[TWEAK_SIZE];

	Assert(data_encrypted);

	if (tweak == NULL)
	{
		size_t	lsn_size, unencr_size;
		char	*c = tweak_loc;

		Assert(block != InvalidBlockNumber);

		/*
		 * LSN is used as encryption IV, so page with invalid LSN shouldn't
		 * have been encrypted.
		 */
		if (XLogRecPtrIsInvalid(PageGetLSN(input)))
		{
			if (input != output)
				memcpy(output, input, size);
			return;
		}

		lsn_size = sizeof(PageXLogRecPtr);

		memset(c, 0, TWEAK_SIZE);
		memcpy(c, input, lsn_size);
		c += lsn_size;
		memcpy(c, &block, sizeof(BlockNumber));

		tweak = tweak_loc;

		if (input != output)
			memcpy(output, input, lsn_size);

		/* Do not encrypt the LSN and checksum. */
		unencr_size = offsetof(PageHeaderData, pd_flags);
		input += unencr_size;
		output += unencr_size;
		size -= unencr_size;
	}
	else if (IsAllZero(input, size))
	{
		if (input != output)
			memset(output, 0, size);
		return;
	}

	ctx = data_kind != EDK_BUFFILE ? ctx_encrypt : ctx_encrypt_buffile;

	/*
	 * The amount of decrypted data should be a multiple of the encryption
	 * block size.
	 */
#ifdef USE_ASSERT_CHECKING
	if (EVP_CIPHER_CTX_block_size(ctx) > 1)
		Assert(size % EVP_CIPHER_CTX_block_size(ctx) == 0);
#endif

	/* The remaining initialization. */
	if (EVP_DecryptInit_ex(ctx, NULL, NULL, encryption_key,
						   (unsigned char *) tweak) != 1)
		evp_error();

	/* Do the actual encryption. */
	if (EVP_DecryptUpdate(ctx, (unsigned char *) output,
						  &out_size, (unsigned char *) input, size) != 1)
		evp_error();

	if (out_size != size)
	{
#ifndef FRONTEND
		ereport(ERROR, (errmsg("Some data left undecrypted")));
#else
		/* Front-end shouldn't actually get here, but be careful. */
		fprintf(stderr, "Some data left undecrypted\n");
		exit(EXIT_FAILURE);
#endif	/* FRONTEND */
	}
#else  /* !USE_ENCRYPTION */
	/* data_encrypted should not be set */
	Assert(false);
#endif							/* USE_ENCRYPTION */
}

#ifdef USE_ENCRYPTION
/*
 * Initialize the OpenSSL context for passed cipher.
 *
 * On server side this happens during postmaster startup, so other processes
 * inherit the initialized context via fork(). There's no reason to do this
 * again and again in encrypt_block() / decrypt_block(), also because we
 * should not handle out-of-memory conditions encountered by OpenSSL in
 * another way than ereport(FATAL). The OOM is much less likely to happen
 * during postmaster startup, and even if it happens, troubleshooting should
 * be easier than if it happened during normal operation.
 *
 * XXX Do we need to call EVP_CIPHER_CTX_cleanup() (via on_proc_exit callback
 * for server processes and other way for front-ends)? Not sure it's
 * necessary, as the initialization does not involve any shared resources
 * (e.g. files).
 */
static void
init_encryption_context(EVP_CIPHER_CTX **ctx_p, bool encrypt, bool buffile)
{
	EVP_CIPHER_CTX *ctx;
	const EVP_CIPHER *cipher = NULL;
	int	key_length = DATA_CIPHER_GET_KEY_LENGTH(data_cipher);

	/*
	 * Currently we use CBC mode for buffile.c because CTR imposes much more
	 * stringent requirements on IV (i.e. the same IV must not be used
	 * repeatedly.)
	 */
	if (key_length == 16)
		cipher = !buffile ? EVP_aes_128_ctr() : EVP_aes_128_cbc();
	else if (key_length == 24)
		cipher = !buffile ? EVP_aes_192_ctr() : EVP_aes_192_cbc();
	else if (key_length == 32)
		cipher = !buffile ? EVP_aes_256_ctr() : EVP_aes_256_cbc();
	else
	{
#ifndef FRONTEND
		ereport(ERROR, (errmsg("invalid key length %d", key_length)));
#else
		/* Front-end shouldn't actually get here, but be careful. */
		fprintf(stderr, "invalid key length %d", key_length);
		exit(EXIT_FAILURE);
#endif	/* FRONTEND */
	}

	if ((*ctx_p = EVP_CIPHER_CTX_new()) == NULL)
		evp_error();
	ctx = *ctx_p;

	if (encrypt)
	{
		if (EVP_EncryptInit_ex(ctx, cipher, NULL, NULL, NULL) != 1)
			evp_error();
	}
	else
	{
		if (EVP_DecryptInit_ex(ctx, cipher, NULL, NULL, NULL) != 1)
			evp_error();
	}

	/* CTR mode is effectively a stream cipher. */
	Assert((!buffile && EVP_CIPHER_CTX_block_size(ctx) == 1) ||
		   (buffile && EVP_CIPHER_CTX_block_size(ctx) == 16));

	/*
	 * No padding is needed. For relation pages the input block size should
	 * already be a multiple of ENCRYPTION_BLOCK, while for WAL we want to
	 * avoid encryption of the unused (zeroed) part of the page, see
	 * backend/storage/file/README.encryption.
	 *
	 * XXX Is this setting worth when we don't call EVP_EncryptFinal_ex()
	 * anyway? (Given the block_size==1, EVP_EncryptFinal_ex() wouldn't do
	 * anything.)
	 */
	EVP_CIPHER_CTX_set_padding(ctx, 0);

	Assert(EVP_CIPHER_CTX_iv_length(ctx) == TWEAK_SIZE);
	Assert(EVP_CIPHER_CTX_key_length(ctx) == key_length);
}

#endif							/* USE_ENCRYPTION */

#ifdef USE_ENCRYPTION
/*
 * Error callback for openssl.
 */
static void
evp_error(void)
{
	ERR_print_errors_fp(stderr);
#ifndef FRONTEND

	/*
	 * FATAL is the appropriate level because backend can hardly fix anything
	 * if encryption / decryption has failed.
	 *
	 * XXX Do we yet need EVP_CIPHER_CTX_cleanup() here?
	 */
	elog(FATAL, "OpenSSL encountered error during encryption or decryption.");
#else
	fprintf(stderr,
			"OpenSSL encountered error during encryption or decryption.");
	exit(EXIT_FAILURE);
#endif							/* FRONTEND */
}
#endif /* USE_ENCRYPTION */

/*
 * Xlog is encrypted page at a time. Each xlog page gets a unique tweak via
 * timeline, segment and offset.
 *
 * The function is located here rather than some of the xlog*.c modules so
 * that front-end applications can easily use it too.
 */
void
XLogEncryptionTweak(char *tweak, TimeLineID timeline, XLogSegNo segment,
					uint32 offset)
{
	memset(tweak, 0, TWEAK_SIZE);
	memcpy(tweak, &timeline, sizeof(timeline));
	tweak += sizeof(timeline);
	memcpy(tweak, &segment, sizeof(XLogSegNo));
	tweak += sizeof(XLogSegNo);
	memcpy(tweak, &offset, sizeof(offset));
}

/*
 * md files are encrypted block at a time. Tweak will alias higher numbered
 * forks for huge tables.
 */
void
mdtweak(char *tweak, RelFileNode *relnode, ForkNumber forknum, BlockNumber blocknum)
{
	uint32		fork_and_block = (forknum << 24) ^ blocknum;

	memcpy(tweak, relnode, sizeof(RelFileNode));
	memcpy(tweak + sizeof(RelFileNode), &fork_and_block, 4);
}

#ifndef FRONTEND
/*
 * Generate non-fake LSN.
 *
 * XLOG_NOOP is the easiest way to generate a valid LSN. Fake LSN
 * is not suitable for permanent relation because it'd be hard to
 * guarantee that it's not equal to any (existing or future)
 * regular LSN.
 *
 * This approach introduces some overhead (no WAL would be written
 * w/o encryption) but such a small record per page doesn't seem
 * terrible.
 */
XLogRecPtr
get_lsn_for_encryption(void)
{
	char	xlr_data = '\0';
	XLogRecPtr	lsn;

	XLogBeginInsert();
	/* At least 1 byte is required. */
	XLogRegisterData(&xlr_data, 1);
	lsn = XLogInsert(RM_XLOG_ID, XLOG_NOOP);
	return lsn;
}

/*
 * Assign fake LSN to a page.
 */
void
set_page_lsn_for_encryption(Page page)
{
	XLogRecPtr	lsn;

	if (!data_encrypted)
		return;

	lsn = get_lsn_for_encryption();
	PageSetLSN(page, lsn);
}

/*
 * Assign the same fake LSN to two different pages.
 */
void
set_page_lsn_for_encryption2(Page page1, Page page2)
{
	XLogRecPtr	lsn;

	if (!data_encrypted)
		return;

	lsn = get_lsn_for_encryption();
	PageSetLSN(page1, lsn);
	PageSetLSN(page2, lsn);
}

/*
 * Assign the same fake LSN to three different pages.
 */
void
set_page_lsn_for_encryption3(Page page1, Page page2, Page page3)
{
	XLogRecPtr	lsn;

	if (!data_encrypted)
		return;

	lsn = get_lsn_for_encryption();
	PageSetLSN(page1, lsn);
	PageSetLSN(page2, lsn);
	PageSetLSN(page3, lsn);
}
#endif	/* !FRONTEND */
