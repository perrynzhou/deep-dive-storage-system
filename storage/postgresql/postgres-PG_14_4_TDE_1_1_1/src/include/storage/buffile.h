/*-------------------------------------------------------------------------
 *
 * buffile.h
 *	  Management of large buffered temporary files.
 *
 * The BufFile routines provide a partial replacement for stdio atop
 * virtual file descriptors managed by fd.c.  Currently they only support
 * buffered access to a virtual file, without any of stdio's formatting
 * features.  That's enough for immediate needs, but the set of facilities
 * could be expanded if necessary.
 *
 * BufFile also supports working with temporary files that exceed the OS
 * file size limit and/or the largest offset representable in an int.
 * It might be better to split that out as a separately accessible module,
 * but currently we have no need for oversize temp files without buffered
 * access.
 *
 * Portions Copyright (c) 2019-2022, CYBERTEC PostgreSQL International GmbH
 * Portions Copyright (c) 1996-2022, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * src/include/storage/buffile.h
 *
 *-------------------------------------------------------------------------
 */

#ifndef BUFFILE_H
#define BUFFILE_H

#include "storage/encryption.h"
#include "storage/sharedfileset.h"

/*
 * BufFile and TransientBufFile are opaque types whose details are not known
 * outside buffile.c.
 */

typedef struct BufFile BufFile;
typedef struct TransientBufFile TransientBufFile;

/*
 * If the file is encrypted, some metadata is needed for each buffer. Thus we
 * can only start load/dump at an offset that is a whole multiple of BLCKSZ.
 */
typedef struct BufFilePageHeader
{
	/* The encryption IV. */
	char		tweak[TWEAK_SIZE];

	/*
	 * The number of useful bytes in the buffer, the rest is only padding up
	 * to BLCKSZ. Note that this field is included in the encrypted region.
	 */
	int16	nbytes;
} BufFilePageHeader;

#define	SizeOfBufFilePageHeader	(offsetof(BufFilePageHeader, nbytes) + sizeof(int16))

/*
 * Express segment size in the number of blocks.
 *
 * We break BufFiles into gigabyte-sized segments, regardless of RELSEG_SIZE.
 * The reason is that we'd like large BufFiles to be spread across multiple
 * tablespaces when available.
 */
#define BUFFILE_SEG_BLOCKS	0x20000

#define MAX_PHYSICAL_FILESIZE(blocks)	((blocks) * BLCKSZ)

/* GUC to control size of the file segment. */
extern int buffile_seg_blocks;

/* Segment size in bytes, derived from the above. */
extern int buffile_max_filesize;

/* Number of BLCKSZ chunks that user can write into a single segment file. */
extern int buffile_seg_blocks_logical;

/* The amount of data a full segment file occupies on disk. */
#define	BYTES_PER_SEGMENT	(buffile_seg_blocks * BLCKSZ)

/*
 * The amount of data user can write into a single segment file. If the
 * instance is encrypted, this is lower than BYTES_PER_SEGMENT because the
 * file blocks contain metadata (headers).
 */
#define	BYTES_PER_SEGMENT_LOGICAL	(buffile_seg_blocks_logical * BLCKSZ)

/*
 * User of buffile.c should only be interested in the logical position. The
 * physical position is the same for unencrypted file, however it's different
 * for encrypted file due to the presence of BufFilePageHeader.
 */
static inline off_t
BufFileLogicalToPhysicalPos(off_t pos)
{
	off_t	last_seg_bytes, result;
	int	full_segs;

	if (!data_encrypted)
		return pos;

	full_segs = pos / BYTES_PER_SEGMENT_LOGICAL;
	result = full_segs * BYTES_PER_SEGMENT;

	last_seg_bytes = pos % BYTES_PER_SEGMENT_LOGICAL;
	if (last_seg_bytes > 0)
	{
		off_t	full_blocks;
		int		last_block_usage;
		int		useful_per_block = BLCKSZ - SizeOfBufFilePageHeader;

		full_blocks = last_seg_bytes / useful_per_block;
		result += full_blocks * BLCKSZ;

		last_block_usage = last_seg_bytes % useful_per_block;
		if (last_block_usage > 0)
			result += last_block_usage;
	}

	/*
	 * Even if we're at block boundary, add the header size so that we end
	 * up at usable position.
	 */
	result += SizeOfBufFilePageHeader;

	return result;
}

static inline off_t
BufFilePhysicalToLogicalPos(off_t pos)
{
	int		full_segs;
	off_t	last_seg_bytes, result;

	if (!data_encrypted)
		return pos;

	full_segs = pos / BYTES_PER_SEGMENT;
	result = full_segs * BYTES_PER_SEGMENT_LOGICAL;

	last_seg_bytes = pos % BYTES_PER_SEGMENT;
	if (last_seg_bytes > 0)
	{
		off_t	full_blocks;
		int		last_block_usage;

		full_blocks = last_seg_bytes / BLCKSZ;
		last_block_usage = last_seg_bytes % BLCKSZ;

		result += full_blocks * (BLCKSZ - SizeOfBufFilePageHeader);
		if (last_block_usage > 0)
			result += last_block_usage - SizeOfBufFilePageHeader;
	}

	return result;
}

/*
 * prototypes for functions in buffile.c
 */
extern void BufFileAdjustConfiguration(int buffile_seg_blocks);
extern BufFile *BufFileCreateTemp(bool interXact);
extern void BufFileClose(BufFile *file);
extern size_t BufFileRead(BufFile *file, void *ptr, size_t size);
extern size_t BufFileWrite(BufFile *file, void *ptr, size_t size);
extern int	BufFileSeek(BufFile *file, int fileno, off_t offset, int whence);
extern void BufFileTell(BufFile *file, int *fileno, off_t *offset);
extern int	BufFileSeekBlock(BufFile *file, long blknum);
extern int64 BufFileSize(BufFile *file);
extern long BufFileAppend(BufFile *target, BufFile *source);

extern BufFile *BufFileCreateShared(SharedFileSet *fileset, const char *name);
extern void BufFileExportShared(BufFile *file);
extern BufFile *BufFileOpenShared(SharedFileSet *fileset, const char *name,
								  int mode);
extern void BufFileDeleteShared(SharedFileSet *fileset, const char *name);
extern void BufFileTruncateShared(BufFile *file, int fileno, off_t offset);

extern TransientBufFile *BufFileOpenTransient(const char *path, int fileFlags);
extern void BufFileCloseTransient(TransientBufFile *file);
extern File BufFileTransientGetVfd(TransientBufFile *file);
extern size_t BufFileReadTransient(TransientBufFile *file, void *ptr,
					 size_t size);
extern size_t BufFileWriteTransient(TransientBufFile *file, void *ptr,
					  size_t size);

#endif							/* BUFFILE_H */
