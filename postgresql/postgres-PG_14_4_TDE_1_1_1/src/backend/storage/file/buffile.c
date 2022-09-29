/*-------------------------------------------------------------------------
 *
 * buffile.c
 *	  Management of large buffered temporary files.
 *
 * Portions Copyright (c) 2019-2022, CYBERTEC PostgreSQL International GmbH
 * Portions Copyright (c) 1996-2022, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * IDENTIFICATION
 *	  src/backend/storage/file/buffile.c
 *
 * NOTES:
 *
 * BufFiles provide a very incomplete emulation of stdio atop virtual Files
 * (as managed by fd.c).  Currently, we only support the buffered-I/O
 * aspect of stdio: a read or write of the low-level File occurs only
 * when the buffer is filled or emptied.  This is an even bigger win
 * for virtual Files than for ordinary kernel files, since reducing the
 * frequency with which a virtual File is touched reduces "thrashing"
 * of opening/closing file descriptors.
 *
 * Note that BufFile structs are allocated with palloc(), and therefore
 * will go away automatically at query/transaction end.  Since the underlying
 * virtual Files are made with OpenTemporaryFile, all resources for
 * the file are certain to be cleaned up even if processing is aborted
 * by ereport(ERROR).  The data structures required are made in the
 * palloc context that was current when the BufFile was created, and
 * any external resources such as temp files are owned by the ResourceOwner
 * that was current at that time.
 *
 * BufFile also supports temporary files that exceed the OS file size limit
 * (by opening multiple fd.c temporary files).  This is an essential feature
 * for sorts and hashjoins on large amounts of data.
 *
 * BufFile supports temporary files that can be shared with other backends, as
 * infrastructure for parallel execution.  Such files need to be created as a
 * member of a SharedFileSet that all participants are attached to.
 *
 * BufFile also supports temporary files that can be used by the single backend
 * when the corresponding files need to be survived across the transaction and
 * need to be opened and closed multiple times.  Such files need to be created
 * as a member of a SharedFileSet.
 *-------------------------------------------------------------------------
 */

#include "postgres.h"

#include <unistd.h>

#include "commands/tablespace.h"
#include "common/string.h"
#include "executor/instrument.h"
#include "miscadmin.h"
#include "pgstat.h"
#include "storage/buf_internals.h"
#include "storage/buffile.h"
#include "storage/fd.h"
#include "utils/datetime.h"
#include "utils/resowner.h"

/*
 * Unlike PG core, we implement these parameters as GUC so that crossing of
 * segment boundaries can be tested easily. Note also that we derive
 * buffile_max_filesize from buffile_seg_blocks, not the other way round. It'd
 * be weird to let user set buffile_max_filesize directly because it's usually
 * adjusted in an encrypted cluster (see assign_buffile_seg_blocks()).
 */
int buffile_seg_blocks	=	BUFFILE_SEG_BLOCKS;
int buffile_max_filesize	=  MAX_PHYSICAL_FILESIZE(BUFFILE_SEG_BLOCKS);

/*
 * The following is only relevant to encrypted cluster.
 *
 * To make sure that BufFileLogicalToPhysicalPos() and
 * BufFilePhysicalToLogicalPos() can handle segment file boundaries despite
 * BufFileAppend() creates holes in the temporary file, we ensure that user
 * can only write a whole multiple of BLCKSZ-sized chunks of payload into a
 * segment file.
 *
 * Thus buffile_seg_blocks_logical is the number of BLCKSZ chunks that the
 * user can write into a segment file. When computing the value, we also
 * adjust buffile_max_filesize (see assign_buffile_seg_blocks()) so that the
 * segment file does not accept any data beyond the last "logical
 * block". (Actually we encrypt BLCKSZ bytes at a time, so the unused part of
 * the last "physical" buffer will be written to disk too.)
 *
 * The fact that the first logical block of the next segment file is at the
 * beginning of that file also allows BufFileAppend() to return a (logical)
 * block number that can be passed to BufFileSeekBlock(). Otherwise
 * BufFileSeekBlock() would think that the desired physical position is in the
 * hole created by BufFileAppend().
 */
int buffile_seg_blocks_logical	=	BUFFILE_SEG_BLOCKS;

/* Have we already run BufFileAdjustConfiguration()? */
static bool	conf_adjusted = false;

/*
 * Compute buffile_max_filesize and buffile_seg_blocks_logical out of
 * buffile_seg_blocks.
 */
void
BufFileAdjustConfiguration(int buffile_seg_blocks)
{
	if (!data_encrypted)
	{
		buffile_max_filesize = MAX_PHYSICAL_FILESIZE(buffile_seg_blocks);
		buffile_seg_blocks_logical = buffile_seg_blocks;
	}
	else
	{
		off_t	useful, last_block_usage;
		int		blocks;

		/*
		 * The useful space, including the incomplete last chunk of BLCKSZ
		 * bytes.
		 */
		useful = buffile_seg_blocks * (BLCKSZ - SizeOfBufFilePageHeader);
		/* Round down to a multiple of BLCKSZ - only this part can be used. */
		useful -= useful % BLCKSZ;
		/* Fully used (physical) blocks needed. */
		blocks = useful / (BLCKSZ - SizeOfBufFilePageHeader);
		/* Space needed in the last (only partially used) physical block. */
		last_block_usage = useful % (BLCKSZ - SizeOfBufFilePageHeader);

		/* Compute the physical offset. */
		buffile_max_filesize = blocks * BLCKSZ;
		if (last_block_usage > 0)
			buffile_max_filesize += SizeOfBufFilePageHeader +
				last_block_usage;

		/* How many chunks can the user write? */
		buffile_seg_blocks_logical = useful / BLCKSZ;
	}
}

/*
 * Fields that both BufFile and TransientBufFile structures need. It must be
 * the first field of those structures.
 */
typedef struct BufFileCommon
{
	bool		dirty;			/* does buffer need to be written? */
	int			pos;			/* next read/write position in buffer */
	int			nbytes;			/* total # of valid bytes in buffer */

	/*
	 * "current pos" is position of start of buffer within the logical file.
	 * Position as seen by user of BufFile is (curFile, curOffset + pos).
	 */
	int			curFile;		/* file index (0..n) part of current pos,
								 * always zero for TransientBufFile */
	off_t		curOffset;		/* offset part of current pos */

	bool		readOnly;		/* has the file been set to read only? */

	bool		append;			/* should new data be appended to the end? */

	PGAlignedBlock buffer;
} BufFileCommon;

/*
 * The convention is that in an encrypted file, nbytes should be exactly
 * SizeOfBufFilePageHeader if no data could be loaded.
 */
#define BUFFER_IS_EMPTY(file) ((file)->nbytes <= 0 || \
							   (data_encrypted && (file)->nbytes == SizeOfBufFilePageHeader))

/*
 * Sometimes it's useful to cache the segment size, so wrap the file
 * descriptor and the size into this structure.
 */
typedef struct BufFileSegment
{
	File	vfd;
	uint64	size;
} BufFileSegment;

#define	InvalidSegmentSize	0xffffffffffffffff

/*
 * This data structure represents a buffered file that consists of one or
 * more physical files (each accessed through a virtual file descriptor
 * managed by fd.c).
 */
struct BufFile
{
	BufFileCommon common;		/* Common fields, see above. */

	int			numFiles;		/* number of physical files in set */

	BufFileSegment	*files;			/* palloc'd array with numFiles entries */

	bool		isInterXact;	/* keep open over transactions? */

	SharedFileSet *fileset;		/* space for segment files if shared */
	const char *name;			/* name of this BufFile if shared */

	/*
	 * resowner is the ResourceOwner to use for underlying temp files.  (We
	 * don't need to remember the memory context we're using explicitly,
	 * because after creation we only repalloc our arrays larger.)
	 */
	ResourceOwner resowner;
};

/*
 * Buffered variant of a transient file. Unlike BufFile this is simpler in
 * several ways: 1) it's not split into segments, 2) there's no need of seek,
 * 3) there's no need to combine read and write access.
 *
 * XXX "Transient" refers to the fact that this kind of file was initially
 * used to encrypt files that PG core accessed via OpenTransientFile /
 * CloseTransientFile. However, since commit d2070380, PG core uses
 * PathNameOpenFile in reorderbuffer.c., so it was changed here too. Should
 * this structure and related functions be renamed?
 */
struct TransientBufFile
{
	/* Common fields, see above. */
	BufFileCommon common;

	/* The underlying file. */
	BufFileSegment	file;;
	char		*path;
};

/*
 * This counter is used to generate the encryption tweak, see
 * BufFileTweak().
 */
static	uint64	blocks_written = 0;

static BufFile *makeBufFileCommon(int nfiles);
static BufFile *makeBufFile(File firstfile);
static void extendBufFile(BufFile *file);
static void BufFileLoadBuffer(BufFile *file);
static void BufFileDumpBuffer(BufFile *file);
static void BufFileDumpBufferEncrypted(BufFile *file, bool last_in_segment);
static void BufFileFlush(BufFile *file);
static File MakeNewSharedSegment(BufFile *file, int segment);

static void BufFileTweak(char *tweak, BufFileCommon *file);
static int64 BufFileSegmentSize(BufFileSegment *seg);
static bool BufFileLastBlock(BufFileCommon *file, int *numSegments);

static void BufFileLoadBufferTransient(TransientBufFile *file);
static void BufFileDumpBufferTransient(TransientBufFile *file);

static size_t BufFileReadCommon(BufFileCommon *file, void *ptr, size_t size,
								int *numSegments);
static size_t BufFileWriteCommon(BufFileCommon *file, void *ptr, size_t size,
								 bool is_transient);
static int16 BufFileGetUsefulBytes(File segment, off_t offset,
								   PGAlignedBlock *buffer);
static void BufFileAdjustUsefulBytes(BufFileCommon *file,
									 BufFileSegment *segments);

/*
 * Create BufFile and perform the common initialization.
 */
static BufFile *
makeBufFileCommon(int nfiles)
{
	BufFile    *file = (BufFile *) palloc0(sizeof(BufFile));
	BufFileCommon *fcommon = &file->common;

	/*
	 * Make sure that BufFileAdjustConfiguration() has been run before the
	 * first use of temporary file. The GUC assign_hook will call the function
	 * whenever buffile_seg_blocks gets changed, however it does not help
	 * during startup: when the GUC subsystem is initialized, data_encrypted
	 * is still false.
	 */
	if (data_encrypted && !conf_adjusted)
	{
		BufFileAdjustConfiguration(buffile_seg_blocks);
		conf_adjusted = true;
	}

	fcommon->dirty = false;
	fcommon->curFile = 0;
	fcommon->curOffset = 0L;
	if (!data_encrypted)
		fcommon->pos = fcommon->nbytes = 0;
	else
		fcommon->pos = fcommon->nbytes = SizeOfBufFilePageHeader;

	file->numFiles = nfiles;
	file->isInterXact = false;
	file->resowner = CurrentResourceOwner;

	return file;
}

/*
 * Create a BufFile given the first underlying physical file.
 * NOTE: caller must set isInterXact if appropriate.
 */
static BufFile *
makeBufFile(File firstfile)
{
	BufFile    *file = makeBufFileCommon(1);

	file->files = (BufFileSegment *) palloc(sizeof(BufFileSegment));
	file->files[0].vfd = firstfile;
	file->files[0].size = InvalidSegmentSize;
	file->common.readOnly = false;
	file->fileset = NULL;
	file->name = NULL;

	return file;
}

/*
 * Add another component temp file.
 */
static void
extendBufFile(BufFile *file)
{
	File		pfile;
	ResourceOwner oldowner;

	/* Be sure to associate the file with the BufFile's resource owner */
	oldowner = CurrentResourceOwner;
	CurrentResourceOwner = file->resowner;

	if (file->fileset == NULL)
		pfile = OpenTemporaryFile(file->isInterXact);
	else
		pfile = MakeNewSharedSegment(file, file->numFiles);

	Assert(pfile >= 0);

	CurrentResourceOwner = oldowner;

	file->files = (BufFileSegment *) repalloc(file->files,
											  (file->numFiles + 1) * sizeof(BufFileSegment));
	file->files[file->numFiles].vfd = pfile;
	file->files[file->numFiles].size = InvalidSegmentSize;

	file->numFiles++;
}

/*
 * Create a BufFile for a new temporary file (which will expand to become
 * multiple temporary files if more than buffile_max_filesize bytes are
 * written to it).
 *
 * If interXact is true, the temp file will not be automatically deleted
 * at end of transaction.
 *
 * Note: if interXact is true, the caller had better be calling us in a
 * memory context, and with a resource owner, that will survive across
 * transaction boundaries.
 */
BufFile *
BufFileCreateTemp(bool interXact)
{
	BufFile    *file;
	File		pfile;

	/*
	 * Ensure that temp tablespaces are set up for OpenTemporaryFile to use.
	 * Possibly the caller will have done this already, but it seems useful to
	 * double-check here.  Failure to do this at all would result in the temp
	 * files always getting placed in the default tablespace, which is a
	 * pretty hard-to-detect bug.  Callers may prefer to do it earlier if they
	 * want to be sure that any required catalog access is done in some other
	 * resource context.
	 */
	PrepareTempTablespaces();

	pfile = OpenTemporaryFile(interXact);
	Assert(pfile >= 0);

	file = makeBufFile(pfile);
	file->isInterXact = interXact;

	return file;
}

/*
 * Build the name for a given segment of a given BufFile.
 */
static void
SharedSegmentName(char *name, const char *buffile_name, int segment)
{
	snprintf(name, MAXPGPATH, "%s.%d", buffile_name, segment);
}

/*
 * Create a new segment file backing a shared BufFile.
 */
static File
MakeNewSharedSegment(BufFile *buffile, int segment)
{
	char		name[MAXPGPATH];
	File		file;

	/*
	 * It is possible that there are files left over from before a crash
	 * restart with the same name.  In order for BufFileOpenShared() not to
	 * get confused about how many segments there are, we'll unlink the next
	 * segment number if it already exists.
	 */
	SharedSegmentName(name, buffile->name, segment + 1);
	SharedFileSetDelete(buffile->fileset, name, true);

	/* Create the new segment. */
	SharedSegmentName(name, buffile->name, segment);
	file = SharedFileSetCreate(buffile->fileset, name);

	/* SharedFileSetCreate would've errored out */
	Assert(file > 0);

	return file;
}

/*
 * Create a BufFile that can be discovered and opened read-only by other
 * backends that are attached to the same SharedFileSet using the same name.
 *
 * The naming scheme for shared BufFiles is left up to the calling code.  The
 * name will appear as part of one or more filenames on disk, and might
 * provide clues to administrators about which subsystem is generating
 * temporary file data.  Since each SharedFileSet object is backed by one or
 * more uniquely named temporary directory, names don't conflict with
 * unrelated SharedFileSet objects.
 */
BufFile *
BufFileCreateShared(SharedFileSet *fileset, const char *name)
{
	BufFile    *file;

	file = makeBufFileCommon(1);
	file->fileset = fileset;
	file->name = pstrdup(name);
	file->files = (BufFileSegment *) palloc(sizeof(BufFileSegment));
	file->files[0].vfd = MakeNewSharedSegment(file, 0);
	file->files[0].size = InvalidSegmentSize;
	file->common.readOnly = false;

	return file;
}

/*
 * Open a file that was previously created in another backend (or this one)
 * with BufFileCreateShared in the same SharedFileSet using the same name.
 * The backend that created the file must have called BufFileClose() or
 * BufFileExportShared() to make sure that it is ready to be opened by other
 * backends and render it read-only.
 */
BufFile *
BufFileOpenShared(SharedFileSet *fileset, const char *name, int mode)
{
	BufFile    *file;
	char		segment_name[MAXPGPATH];
	Size		capacity = 16;
	BufFileSegment   *files;
	int			nfiles = 0;

	files = palloc(sizeof(BufFileSegment) * capacity);

	/*
	 * We don't know how many segments there are, so we'll probe the
	 * filesystem to find out.
	 */
	for (;;)
	{
		/* See if we need to expand our file segment array. */
		if (nfiles + 1 > capacity)
		{
			capacity *= 2;
			files = repalloc(files, sizeof(BufFileSegment) * capacity);
		}
		/* Try to load a segment. */
		SharedSegmentName(segment_name, name, nfiles);
		files[nfiles].vfd = SharedFileSetOpen(fileset, segment_name, mode);
		if (files[nfiles].vfd <= 0)
			break;
		files[nfiles].size = InvalidSegmentSize;

		++nfiles;

		CHECK_FOR_INTERRUPTS();
	}

	/*
	 * If we didn't find any files at all, then no BufFile exists with this
	 * name.
	 */
	if (nfiles == 0)
		ereport(ERROR,
				(errcode_for_file_access(),
				 errmsg("could not open temporary file \"%s\" from BufFile \"%s\": %m",
						segment_name, name)));

	file = makeBufFileCommon(nfiles);

	file->files = files;
	file->common.readOnly = (mode == O_RDONLY) ? true : false;
	file->fileset = fileset;
	file->name = pstrdup(name);

	/*
	 * Load the buffer if needed.
	 *
	 * BufFileReadCommon() could do that lazily but it'd get more complex
	 * because initially nbytes is not a multiple of BLCKSZ.
	 */
	if (data_encrypted)
		BufFileLoadBuffer(file);

	return file;
}

/*
 * Delete a BufFile that was created by BufFileCreateShared in the given
 * SharedFileSet using the given name.
 *
 * It is not necessary to delete files explicitly with this function.  It is
 * provided only as a way to delete files proactively, rather than waiting for
 * the SharedFileSet to be cleaned up.
 *
 * Only one backend should attempt to delete a given name, and should know
 * that it exists and has been exported or closed.
 */
void
BufFileDeleteShared(SharedFileSet *fileset, const char *name)
{
	char		segment_name[MAXPGPATH];
	int			segment = 0;
	bool		found = false;

	/*
	 * We don't know how many segments the file has.  We'll keep deleting
	 * until we run out.  If we don't manage to find even an initial segment,
	 * raise an error.
	 */
	for (;;)
	{
		SharedSegmentName(segment_name, name, segment);
		if (!SharedFileSetDelete(fileset, segment_name, true))
			break;
		found = true;
		++segment;

		CHECK_FOR_INTERRUPTS();
	}

	if (!found)
		elog(ERROR, "could not delete unknown shared BufFile \"%s\"", name);
}

/*
 * BufFileExportShared --- flush and make read-only, in preparation for sharing.
 */
void
BufFileExportShared(BufFile *file)
{
	/* Must be a file belonging to a SharedFileSet. */
	Assert(file->fileset != NULL);

	/* It's probably a bug if someone calls this twice. */
	Assert(!file->common.readOnly);

	BufFileFlush(file);
	file->common.readOnly = true;
}

/*
 * Close a BufFile
 *
 * Like fclose(), this also implicitly FileCloses the underlying File.
 */
void
BufFileClose(BufFile *file)
{
	int			i;

	/* flush any unwritten data */
	BufFileFlush(file);
	/* close and delete the underlying file(s) */
	for (i = 0; i < file->numFiles; i++)
		FileClose(file->files[i].vfd);
	/* release the buffer space */
	pfree(file->files);
	pfree(file);
}

/*
 * BufFileLoadBuffer
 *
 * Load some data into buffer, if possible, starting from curOffset.
 * At call, must have dirty = false, nbytes = 0.
 * On exit, nbytes is number of bytes loaded.
 */
static void
BufFileLoadBuffer(BufFile *file)
{
	BufFileCommon	*f = &file->common;
	BufFileSegment		*thisfile;

	/*
	 * Only whole multiple of BLCKSZ can be encrypted / decrypted.
	 */
	Assert(f->curOffset % BLCKSZ == 0 || !data_encrypted);

	/*
	 * Advance to next component file if necessary and possible.
	 */
	if (f->curOffset >= buffile_max_filesize &&
		f->curFile + 1 < file->numFiles)
	{
		f->curFile++;
		f->curOffset = 0L;
	}

	/*
	 * Read whatever we can get, up to a full bufferload.
	 */
	thisfile = &file->files[f->curFile];
	f->nbytes = FileRead(thisfile->vfd,
						 f->buffer.data,
						 sizeof(f->buffer),
						 f->curOffset,
						 WAIT_EVENT_BUFFILE_READ);
	if (f->nbytes < 0)
	{
		f->nbytes = 0;
		ereport(ERROR,
				(errcode_for_file_access(),
				 errmsg("could not read file \"%s\": %m",
						FilePathName(thisfile->vfd))));
	}

	/* we choose not to advance curOffset here */

	if (data_encrypted)
		BufFileAdjustUsefulBytes(f, file->files);

	if (f->nbytes > 0)
		pgBufferUsage.temp_blks_read++;
}

/*
 * BufFileDumpBuffer
 *
 * Dump buffer contents starting at curOffset.
 * At call, should have dirty = true, nbytes > 0.
 * On exit, dirty is cleared if successful write, and curOffset is advanced.
 */
static void
BufFileDumpBuffer(BufFile *file)
{
	int			wpos = 0;
	int			bytestowrite;
	BufFileSegment		*thisfile;

	/*
	 * Unlike BufFileLoadBuffer, we must dump the whole buffer even if it
	 * crosses a component-file boundary; so we need a loop.
	 */
	while (wpos < file->common.nbytes)
	{
		off_t		availbytes;

		/*
		 * Advance to next component file if necessary and possible.
		 */
		if (file->common.curOffset >= buffile_max_filesize)
		{
			while (file->common.curFile + 1 >= file->numFiles)
				extendBufFile(file);
			file->common.curFile++;
			file->common.curOffset = 0L;
		}

		/*
		 * Determine how much we need to write into this file.
		 */
		bytestowrite = file->common.nbytes - wpos;
		availbytes = buffile_max_filesize - file->common.curOffset;

		if ((off_t) bytestowrite > availbytes)
			bytestowrite = (int) availbytes;

		thisfile = &file->files[file->common.curFile];
		bytestowrite = FileWrite(thisfile->vfd,
								 file->common.buffer.data + wpos,
								 bytestowrite,
								 file->common.curOffset,
								 WAIT_EVENT_BUFFILE_WRITE);
		if (bytestowrite <= 0)
			ereport(ERROR,
					(errcode_for_file_access(),
					 errmsg("could not write to file \"%s\": %m",
							FilePathName(thisfile->vfd))));

		/* Set or update the cached size. */
		if (thisfile->size == InvalidSegmentSize ||
			(file->common.curOffset + bytestowrite) > thisfile->size)
			thisfile->size = file->common.curOffset + bytestowrite;

		file->common.curOffset += bytestowrite;
		wpos += bytestowrite;

		pgBufferUsage.temp_blks_written++;
	}
	file->common.dirty = false;

	/*
	 * At this point, curOffset has been advanced to the end of the buffer,
	 * ie, its original value + nbytes.  We need to make it point to the
	 * logical file position, ie, original value + pos, in case that is less
	 * (as could happen due to a small backwards seek in a dirty buffer!)
	 */
	file->common.curOffset -= (file->common.nbytes - file->common.pos);
	if (file->common.curOffset < 0) /* handle possible segment crossing */
	{
		file->common.curFile--;
		Assert(file->common.curFile >= 0);
		file->common.curOffset += buffile_max_filesize;
	}

	/*
	 * Now we can set the buffer empty without changing the logical position
	 */
	file->common.pos = 0;
	file->common.nbytes = 0;
}

/*
 * BufFileDumpBufferEncrypted
 *
 * Encrypt buffer and dump it. The functionality is sufficiently different
 * from BufFileDumpBuffer to be implemented as a separate function. The most
 * notable difference is that no loop is needed here.
 *
 * last_in_segment tells that this should be the last buffer in the segment
 * file, i.e. curOffset should be advanced even if the buffer is not
 * full. Pass false if you don't know/care.
 */
static void
BufFileDumpBufferEncrypted(BufFile *file, bool last_in_segment)
{
	int			bytestowrite;
	BufFileSegment		*thisfile;
	BufFilePageHeader	*hdr;

	/*
	 * Caller's responsibility.
	 */
	Assert(file->common.pos <= file->common.nbytes);

	/*
	 * See comments in BufFileLoadBuffer();
	 */
	Assert(file->common.curOffset % BLCKSZ == 0);

	/*
	 * Advance to next component file if necessary and possible.
	 */
	if (file->common.curOffset >= buffile_max_filesize)
	{
		while (file->common.curFile + 1 >= file->numFiles)
			extendBufFile(file);
		file->common.curFile++;
		file->common.curOffset = 0L;
	}

	/*
	 * Keep curOffset aligned to BLCKSZ.
	 *
	 * Unlike BufFileDumpBuffer(), we don't have to check here how much data
	 * is available in the segment. According to the code above, currOffset
	 * should be lower than buffile_max_filesize by non-zero multiple of
	 * BLCKSZ.
	 */
	bytestowrite = BLCKSZ;

	/*
	 * Fill-in the page header and encrypt everything except for the IV.
	 */
	hdr = (BufFilePageHeader *) file->common.buffer.data;
	BufFileTweak(hdr->tweak, &file->common);
	Assert(file->common.nbytes >= SizeOfBufFilePageHeader);
	hdr->nbytes = file->common.nbytes;
	encrypt_block(file->common.buffer.data + TWEAK_SIZE,
				  encrypt_buf.data + TWEAK_SIZE,
				  BLCKSZ - TWEAK_SIZE,
				  hdr->tweak,
				  InvalidXLogRecPtr,
				  InvalidBlockNumber,
				  EDK_BUFFILE);
	/* Copy the encrypted tweak. */
	memcpy(encrypt_buf.data, hdr->tweak, TWEAK_SIZE);

	thisfile = &file->files[file->common.curFile];
	bytestowrite = FileWrite(thisfile->vfd,
							 encrypt_buf.data,
							 bytestowrite,
							 file->common.curOffset,
							 WAIT_EVENT_BUFFILE_WRITE);

	/* Set or update the cached size. */
	if (thisfile->size == InvalidSegmentSize ||
		(file->common.curOffset + bytestowrite) > thisfile->size)
		thisfile->size = file->common.curOffset + bytestowrite;

	if (bytestowrite <= 0 || bytestowrite != BLCKSZ)
		ereport(ERROR,
				(errcode_for_file_access(),
				 errmsg("could not write to file \"%s\": %m",
						FilePathName(thisfile->vfd))));

	file->common.curOffset += bytestowrite;

	/* Wasn't last_in_segment passed for non-last buffer? */
	Assert(file->common.curOffset >= buffile_max_filesize ||
		   !last_in_segment);

	pgBufferUsage.temp_blks_written++;
	/* For encryption purposes, see BufFileTweak().*/
	blocks_written++;

	file->common.dirty = false;

	if (file->common.pos >= BLCKSZ || last_in_segment)
	{
		Assert(file->common.pos == BLCKSZ || last_in_segment);

		/*
		 * curOffset points to the beginning of the next buffer, so just reset
		 * pos and nbytes.
		 */
		file->common.pos = file->common.nbytes = SizeOfBufFilePageHeader;
	}
	else
	{
		/*
		 * Move curOffset to the beginning of the just-written buffer so it
		 * stays at BLCKSZ boundary, and preserve pos.
		 */
		file->common.curOffset -= BLCKSZ;
	}
}

/*
 * BufFileRead
 *
 * Like fread() except we assume 1-byte element size and report I/O errors via
 * ereport().
 */
size_t
BufFileRead(BufFile *file, void *ptr, size_t size)
{
	return BufFileReadCommon(&file->common, ptr, size, &file->numFiles);
}

/*
 * BufFileWrite
 *
 * Like fwrite() except we assume 1-byte element size and report errors via
 * ereport().
 */
size_t
BufFileWrite(BufFile *file, void *ptr, size_t size)
{
	return BufFileWriteCommon(&file->common, ptr, size, false);
}

/*
 * BufFileFlush
 *
 * Like fflush(), except that I/O errors are reported with ereport().
 */
static void
BufFileFlush(BufFile *file)
{
	if (file->common.dirty)
	{
		if (!data_encrypted)
			BufFileDumpBuffer(file);
		else
			BufFileDumpBufferEncrypted(file, false);
	}

	Assert(!file->common.dirty);
}

/*
 * BufFileSeek
 *
 * Like fseek(), except that target position needs two values in order to
 * work when logical filesize exceeds maximum value representable by off_t.
 * We do not support relative seeks across more than that, however.
 * I/O errors are reported by ereport().
 *
 * Result is 0 if OK, EOF if not.  Logical position is not moved if an
 * impossible seek is attempted.
 */
int
BufFileSeek(BufFile *file, int fileno, off_t offset, int whence)
{
	int			newFile;
	off_t		newOffset;
	BufFileSegment	*lastSeg;
	bool		end_of_segment = false;

	switch (whence)
	{
		case SEEK_SET:
			if (fileno < 0)
				return EOF;

			if (data_encrypted)
			{
				off_t	pos_log, pos_phys;

				/*
				 * The caller thinks that all BLCKSZ bytes in the block are
				 * usable for the data, so compute the real position in our
				 * file in which each page contains some metadata
				 * (BufFilePageHeader).
				 */
				pos_log = fileno * BYTES_PER_SEGMENT_LOGICAL;

				/*
				 * We don't expect anyone to seek back more than the file
				 * size, otherwise it'd be less trivial to handle negative
				 * offset.
				 */
				Assert(abs(offset) <= pos_log || offset >= 0);

				pos_log += offset;
				pos_phys = BufFileLogicalToPhysicalPos(pos_log);

				fileno = pos_phys / BYTES_PER_SEGMENT;
				offset = pos_phys % BYTES_PER_SEGMENT;
			}

			newFile = fileno;
			newOffset = offset;
			break;
		case SEEK_CUR:

			/*
			 * Relative seek considers only the signed offset, ignoring
			 * fileno. Note that large offsets (> 1 GB) risk overflow in this
			 * add, unless we have 64-bit off_t.
			 */
			if (!data_encrypted)
			{
				newFile = file->common.curFile;
				newOffset = (file->common.curOffset + file->common.pos) + offset;
			}
			else
			{
				off_t	pos_log, pos_phys;

				/* 'offset' is the logical position, so treat it accordingly */
				pos_phys = file->common.curFile * BYTES_PER_SEGMENT +
					file->common.curOffset + file->common.pos;
				pos_log = BufFilePhysicalToLogicalPos(pos_phys);

				/*
				 * We don't expect anyone to seek back more than the file
				 * size, otherwise it'd be less trivial to handle negative
				 * offset.
				 */
				Assert(abs(offset) <= pos_log || offset >= 0);

				pos_log += offset;
				pos_phys = BufFileLogicalToPhysicalPos(pos_log);

				newFile = pos_phys / BYTES_PER_SEGMENT;
				newOffset = pos_phys % BYTES_PER_SEGMENT;
			}
			break;
		case SEEK_END:

			/* Non-zero position is currently not supported. */
			Assert(fileno == 0 && offset == 0);

			/*
			 * The file size of the last file gives us the end offset of that
			 * file.
			 */
			newFile = file->numFiles - 1;
			lastSeg = &file->files[file->numFiles - 1];
			newOffset = BufFileSegmentSize(lastSeg);

			if (data_encrypted)
			{
				/*
				 * Reading/writing of an encrypted file starts at block
				 * boundary.
				 */
				Assert(newOffset % BLCKSZ == 0);

				/* Adjust the end offset of the segment file. */
				if (newOffset > 0)
				{
					PGAlignedBlock	buffer;

					newOffset -= BLCKSZ;
					newOffset += BufFileGetUsefulBytes(lastSeg->vfd, newOffset,
													   &buffer);
				}
			}
			break;
		default:
			elog(ERROR, "invalid whence: %d", whence);
			return EOF;
	}
	/* Negative offset for data_encrypted had to be handled already. */
	if (!data_encrypted)
	{
		while (newOffset < 0)
		{
			if (--newFile < 0)
				return EOF;
			newOffset += buffile_max_filesize;
		}
	}
	if (newFile == file->common.curFile &&
		newOffset >= file->common.curOffset &&
		newOffset <= file->common.curOffset + file->common.nbytes)
	{
		/*
		 * Seek is to a point within existing buffer; we can just adjust
		 * pos-within-buffer, without flushing buffer.  Note this is OK
		 * whether reading or writing, but buffer remains dirty if we were
		 * writing.
		 */
		file->common.pos = (int) (newOffset - file->common.curOffset);
		return 0;
	}
	/* Otherwise, must reposition buffer, so flush any dirty data */
	BufFileFlush(file);

	/*
	 * At this point and no sooner, check for seek past last segment. The
	 * above flush could have created a new segment, so checking sooner would
	 * not work (at least not with this code).
	 */

	/*
	 * Convert seek to "start of next seg" to "end of last seg". If
	 * data_encrypted, the page header itself is not a reason to increment
	 * newFile right now.
	 */
	if (newFile == file->numFiles &&
		(newOffset == 0 ||
		 (data_encrypted && newOffset == SizeOfBufFilePageHeader)))
	{
		newFile--;
		newOffset = buffile_max_filesize;
		end_of_segment = true;
	}
	while (newOffset > buffile_max_filesize)
	{
		if (++newFile >= file->numFiles)
			return EOF;
		newOffset -= buffile_max_filesize;
	}
	if (newFile >= file->numFiles)
		return EOF;
	/* Seek is OK! */
	file->common.curFile = newFile;
	if (!data_encrypted)
	{
		file->common.curOffset = newOffset;
		file->common.pos = 0;
		file->common.nbytes = 0;
	}
	else
	{
		/* Now we can finally account for the header. */
		if (end_of_segment)
			newOffset = BYTES_PER_SEGMENT + SizeOfBufFilePageHeader;

		/* Offset of an encrypted buffer must be a multiple of BLCKSZ. */
		file->common.pos = newOffset % BLCKSZ;
		file->common.curOffset = newOffset - file->common.pos;
		/* BufFileLoadBuffer() will set nbytes. */

		/*
		 * Load and decrypt the existing part of the buffer. Since curOffset
		 * must be at block boundary (as opposed to setting it to newOffset),
		 * we need to load the data between curOffset and newOffset, otherwise
		 * we could overwrite this part with what the unrelated data we
		 * currently have in the buffer.
		 */
		BufFileLoadBuffer(file);

		if (BUFFER_IS_EMPTY(&file->common))
		{
			/*
			 * The data requested is not in the file, but this is not an
			 * error.
			 */
			return 0;
		}
	}
	return 0;
}

void
BufFileTell(BufFile *file, int *fileno, off_t *offset)
{
	if (!data_encrypted)
	{
		*fileno = file->common.curFile;
		*offset = file->common.curOffset + file->common.pos;
	}
	else
	{
		off_t	pos_phys, pos_log;

		/* Caller should only be interested in the logical offset. */
		pos_phys = file->common.curFile * BYTES_PER_SEGMENT +
			file->common.curOffset + file->common.pos;
		pos_log = BufFilePhysicalToLogicalPos(pos_phys);

		*fileno = pos_log / BYTES_PER_SEGMENT_LOGICAL;
		*offset = pos_log % BYTES_PER_SEGMENT_LOGICAL;
	}
}

/*
 * BufFileSeekBlock --- block-oriented seek
 *
 * Performs absolute seek to the start of the n'th BLCKSZ-sized block of
 * the file.  Note that users of this interface will fail if their files
 * exceed BLCKSZ * LONG_MAX bytes, but that is quite a lot; we don't work
 * with tables bigger than that, either...
 *
 * Result is 0 if OK, EOF if not.  Logical position is not moved if an
 * impossible seek is attempted.
 */
int
BufFileSeekBlock(BufFile *file, long blknum)
{
	if (!data_encrypted)
		return BufFileSeek(file,
						   (int) (blknum / buffile_seg_blocks),
						   (off_t) (blknum % buffile_seg_blocks) * BLCKSZ,
						   SEEK_SET);
	else
		return BufFileSeek(file,
						   (int) (blknum / buffile_seg_blocks_logical),
						   (off_t) (blknum % buffile_seg_blocks_logical) * BLCKSZ,
						   SEEK_SET);
}

static void
BufFileTweak(char *tweak, BufFileCommon *file)
{
	pid_t		pid = MyProcPid;
	char	*c = tweak;

	/* Any unused bytes should always be defined. */
	memset(tweak, 0, TWEAK_SIZE);

	StaticAssertStmt(sizeof(pid) + sizeof(blocks_written) <= TWEAK_SIZE,
					 "tweak components do not fit into TWEAK_SIZE");

	/*
	 * The tweak consists of PID of the backend and the number of blocks
	 * written by the backend so far.
	 */
	memcpy(c, &pid, sizeof(pid));
	c += sizeof(pid);
	memcpy(c, &blocks_written, sizeof(blocks_written));
}

#ifdef NOT_USED
/*
 * BufFileTellBlock --- block-oriented tell
 *
 * Any fractional part of a block in the current seek position is ignored.
 */
long
BufFileTellBlock(BufFile *file)
{
	long		blknum;

	if (!data_encrypted)
	{
		blknum = (file->common.curOffset + file->common.pos) / BLCKSZ;
		blknum += file->common.curFile * buffile_seg_blocks;
		return blknum;
	}
	else
	{
		off_t	pos_phys, pos_log;

		/* Caller should only be interested in the logical offset. */
		pos_phys = file->common.curFile * BYTES_PER_SEGMENT +
			file->common.curOffset + file->common.pos;
		pos_log = BufFilePhysicalToLogicalPos(pos_phys);

		return pos_log / BLCKSZ;
	}
}
#endif

/*
 * Return the current shared BufFile size.
 *
 * Counts any holes left behind by BufFileAppend as part of the size.
 * ereport()s on failure.
 */
int64
BufFileSize(BufFile *file)
{
	BufFileSegment	*lastFile = &file->files[file->numFiles - 1];
	int64		lastFileSize;
	off_t	size;

	/* Get the size of the last physical file. */
	lastFileSize = BufFileSegmentSize(lastFile);

	if (!data_encrypted)
		size = ((file->numFiles - 1) * (int64) buffile_max_filesize) +
			lastFileSize;
	else
	{
		/* Caller should only be interested in the logical size. */
		if (lastFileSize > 0)
		{
			PGAlignedBlock	buffer;
			off_t	last_page, size_phys;
			int	nbytes;


			Assert(lastFileSize % BLCKSZ == 0);
			last_page = lastFileSize - BLCKSZ;
			nbytes = BufFileGetUsefulBytes(lastFile->vfd, last_page, &buffer);
			size_phys = last_page + nbytes;
			lastFileSize = BufFilePhysicalToLogicalPos(size_phys);
		}

		size = (file->numFiles - 1) * BYTES_PER_SEGMENT_LOGICAL +
			lastFileSize;
	}

	return size;
}

/*
 * Return value of given segment size. Check the file only if the size is not
 * cached.
 */
static int64
BufFileSegmentSize(BufFileSegment *seg)
{
	off_t	size;

	if (seg->size != InvalidSegmentSize)
		return seg->size;

	size = FileSize(seg->vfd);
	if (size < 0)
		ereport(ERROR,
				(errcode_for_file_access(),
				 errmsg("could not determine size of temporary file \"%s\": %m",
						FilePathName(seg->vfd))));

	seg->size = size;
	return size;
}

/*
 * Check whether the buffer contains the last block of the temporary file.
 *
 * The meaning of numSegments is as the comment of BufFileReadCommon()
 * explains.
 */
static bool
BufFileLastBlock(BufFileCommon *file, int *numSegments)
{
	bool is_transient = numSegments == NULL;

	/* Should only be called on an encrypted file. */
	Assert(data_encrypted);

	if (is_transient || (file->curFile + 1) == *numSegments)
	{
		uint64	seg_size;
		BufFileSegment	*seg;

		/* The last segment, need to check the size. */

		if (!is_transient)
		{
			BufFile	*bf = (BufFile *) file;

			seg = &bf->files[file->curFile];
		}
		else
		{
			TransientBufFile	*tf = (TransientBufFile *) file;

			seg = &tf->file;
		}
		seg_size = BufFileSegmentSize(seg);

		/* Last block in the file/segment? */
		if ((file->curOffset + BLCKSZ) >= seg_size)
			return true;
		else
			/* Lower than last block. */
			return false;
	}
	else
		/* Lower than the last segment. */
		return false;
}

/*
 * Append the contents of source file (managed within shared fileset) to
 * end of target file (managed within same shared fileset).
 *
 * Note that operation subsumes ownership of underlying resources from
 * "source".  Caller should never call BufFileClose against source having
 * called here first.  Resource owners for source and target must match,
 * too.
 *
 * This operation works by manipulating lists of segment files, so the file
 * content is always appended at a buffile_max_filesize-aligned boundary,
 * typically creating empty holes before the boundary.  These areas do not
 * contain any interesting data, and cannot be read from by caller.
 *
 * Returns the block number within target where the contents of source
 * begins.  Caller should apply this as an offset when working off block
 * positions that are in terms of the original BufFile space.
 */
long
BufFileAppend(BufFile *target, BufFile *source)
{
	long		startBlock;
	int			newNumFiles = target->numFiles + source->numFiles;
	int			i;

	if (!data_encrypted)
		startBlock = target->numFiles * buffile_seg_blocks;
	else
		startBlock = target->numFiles * buffile_seg_blocks_logical;

	Assert(target->fileset != NULL);
	Assert(source->common.readOnly);
	Assert(!source->common.dirty);
	Assert(source->fileset != NULL);

	if (target->resowner != source->resowner)
		elog(ERROR, "could not append BufFile with non-matching resource owner");

	target->files = (BufFileSegment *)
		repalloc(target->files, sizeof(BufFileSegment) * newNumFiles);
	for (i = target->numFiles; i < newNumFiles; i++)
		target->files[i] = source->files[i - target->numFiles];

	target->numFiles = newNumFiles;

	return startBlock;
}

/*
 * Open TransientBufFile at given path or create one if it does not
 * exist. User will be allowed either to write to the file or to read from it,
 * according to fileFlags, but not both.
 */
TransientBufFile *
BufFileOpenTransient(const char *path, int fileFlags)
{
	bool		readOnly;
	bool		append = false;
	TransientBufFile *file;
	BufFileCommon *fcommon;
	File		vfd;

	/* Either read or write mode, but not both. */
	Assert((fileFlags & O_RDWR) == 0);

	/* Check whether user wants read or write access. */
	readOnly = (fileFlags & O_WRONLY) == 0;

	if (data_encrypted)
	{
		/*
		 * In the encryption case, even if user will only be allowed to write,
		 * internally we also need to read, see below.
		 */
		fileFlags &= ~O_WRONLY;
		fileFlags |= O_RDWR;

		/*
		 * We can only emulate the append behavior by setting curOffset to
		 * file size because if the underlying file was opened in append mode,
		 * we could not rewrite the old value of file->common.useful[0] with
		 * data.
		 */
		if (fileFlags & O_APPEND)
		{
			append = true;
			fileFlags &= ~O_APPEND;
		}
	}

	/*
	 * Append mode for read access is not useful, so don't bother implementing
	 * it.
	 */
	Assert(!(readOnly && append));

	errno = 0;
	vfd = PathNameOpenFile(path, fileFlags);
	if (vfd < 0)
	{
		/*
		 * If the file is not there, caller should be able to handle the
		 * condition on his own.
		 */
		if (errno == ENOENT)
			return NULL;

		ereport(ERROR,
				(errcode_for_file_access(),
				 errmsg("could not open file \"%s\": %m", path)));
	}

	file = (TransientBufFile *) palloc0(sizeof(TransientBufFile));
	fcommon = &file->common;
	fcommon->dirty = false;
	if (!data_encrypted)
		fcommon->pos = fcommon->nbytes = 0;
	else
		fcommon->pos = fcommon->nbytes = SizeOfBufFilePageHeader;
	fcommon->readOnly = readOnly;
	fcommon->append = append;
	fcommon->curFile = 0;
	file->file.vfd = vfd;
	file->file.size = InvalidSegmentSize;
	file->path = pstrdup(path);

	if (fcommon->append)
	{
		/* Position the buffer at the end of the file. */
		fcommon->curOffset = BufFileSegmentSize(&file->file);
	}
	else
		fcommon->curOffset = 0L;

	/*
	 * When reading, or when writing in the append mode, we need to consider
	 * the current status of the file.
	 */
	if (data_encrypted && (fcommon->append || readOnly))
	{
		Assert(fcommon->curOffset % BLCKSZ == 0);

		if (fcommon->curOffset > 0)
		{
			/* Load the last block. */
			fcommon->curOffset -= BLCKSZ;
		}
		BufFileLoadBufferTransient(file);

		if (fcommon->append && fcommon->nbytes > 0)
		{
			Assert(fcommon->nbytes >= SizeOfBufFilePageHeader);
			fcommon->pos = fcommon->nbytes;
		}
	}

	return file;
}

/*
 * Close a TransientBufFile.
 */
void
BufFileCloseTransient(TransientBufFile *file)
{
	/* Flush any unwritten data. */
	if (!file->common.readOnly &&
		file->common.dirty && file->common.nbytes > 0)
	{
		BufFileDumpBufferTransient(file);

		if (file->common.dirty)
		{
			ereport(WARNING,
					(errcode_for_file_access(),
					 errmsg("could not flush file \"%s\": %m", file->path)));
		}
	}

	FileClose(file->file.vfd);

	pfree(file->path);
	pfree(file);
}

File
BufFileTransientGetVfd(TransientBufFile *file)
{
	return file->file.vfd;
}

/*
 * Load some data into buffer, if possible, starting from file->offset.  At
 * call, must have dirty = false, pos and nbytes = 0.  On exit, nbytes is
 * number of bytes loaded.
 */
static void
BufFileLoadBufferTransient(TransientBufFile *file)
{
	Assert(!file->common.dirty);

	/*
	 * Read whatever we can get, up to a full bufferload.
	 */
	file->common.nbytes = FileRead(file->file.vfd,
								   file->common.buffer.data,
								   sizeof(file->common.buffer),
								   file->common.curOffset,
								   WAIT_EVENT_BUFFILE_READ);

	if (file->common.nbytes < 0)
		ereport(ERROR,
				(errcode_for_file_access(),
				 errmsg("could not read file \"%s\": %m",
						FilePathName(file->file.vfd))));
	/* we choose not to advance offset here */

	if (!data_encrypted)
		return;

	BufFileAdjustUsefulBytes(&file->common, NULL);
}

/*
 * Write contents of a transient file buffer to disk.
 */
static void
BufFileDumpBufferTransient(TransientBufFile *file)
{
	BufFileSegment	*seg;
	int			bytestowrite,
				nwritten;
	char	   *write_ptr;

	/* This function should only be needed during write access ... */
	Assert(!file->common.readOnly);

	/* ... and if there's some work to do. */
	Assert(file->common.dirty);
	Assert(file->common.nbytes > 0);

	if (!data_encrypted)
	{
		write_ptr = file->common.buffer.data;
		bytestowrite = file->common.nbytes;
	}
	else
	{
		BufFilePageHeader	*hdr;

		/*
		 * Encrypt the whole buffer, see comments of BufFilePageHeader.
		 */
		hdr = (BufFilePageHeader *) file->common.buffer.data;
		BufFileTweak(hdr->tweak, &file->common);
		Assert(file->common.nbytes >= SizeOfBufFilePageHeader);
		hdr->nbytes = file->common.nbytes;
		encrypt_block(file->common.buffer.data + TWEAK_SIZE,
					  encrypt_buf.data + TWEAK_SIZE,
					  BLCKSZ - TWEAK_SIZE,
					  hdr->tweak,
					  InvalidXLogRecPtr,
					  InvalidBlockNumber,
					  EDK_BUFFILE);
		/* Copy the encrypted tweak. */
		memcpy(encrypt_buf.data, hdr->tweak, TWEAK_SIZE);

		write_ptr = encrypt_buf.data;
		bytestowrite = BLCKSZ;
	}

	seg = &file->file;
	nwritten = FileWrite(seg->vfd,
						 write_ptr,
						 bytestowrite,
						 file->common.curOffset,
						 WAIT_EVENT_BUFFILE_WRITE);

	/* For encryption purposes, see BufFileTweak().*/
	blocks_written++;

	/* Set or update the cached size. */
	if (seg->size == InvalidSegmentSize ||
		(file->common.curOffset + nwritten) > seg->size)
		seg->size = file->common.curOffset + nwritten;

	/* if write didn't set errno, assume problem is no disk space */
	if (nwritten != bytestowrite)
		ereport(ERROR,
				(errcode_for_file_access(),
				 errmsg("could not write to file \"%s\": %m",
						FilePathName(seg->vfd))));

	file->common.curOffset += nwritten;
	file->common.dirty = false;

	if (!data_encrypted)
		file->common.pos = file->common.nbytes = 0;
	else
		file->common.pos = file->common.nbytes = SizeOfBufFilePageHeader;
}

/*
 * Like BufFileRead() except it receives pointer to TransientBufFile.
 */
size_t
BufFileReadTransient(TransientBufFile *file, void *ptr, size_t size)
{
	return BufFileReadCommon(&file->common, ptr, size, NULL);
}

/*
 * Like BufFileWrite() except it receives pointer to TransientBufFile.
 */
size_t
BufFileWriteTransient(TransientBufFile *file, void *ptr, size_t size)
{
	return BufFileWriteCommon(&file->common, ptr, size, true);
}

/*
 * BufFileWriteCommon
 *
 * Functionality needed by both BufFileRead() and BufFileReadTransient().
 *
 * numSegments is a pointer to the number of segment files of a temporary
 * file, or NULL if the file is a "transient" file (which always consists of a
 * single segment).
 */
static size_t
BufFileReadCommon(BufFileCommon *file, void *ptr, size_t size,
				  int *numSegments)
{
	size_t		nread = 0;
	size_t		nthistime;
	bool is_transient = numSegments == NULL;

	/*
	 * For encrypted data, even BufFileSeek() tries to load the buffer, so if
	 * the buffer is empty now, there's nothing to read.
	 */
	if (data_encrypted && BUFFER_IS_EMPTY(file))
		return nread;

	BufFileFlush((BufFile *) file);

	while (size > 0)
	{
		if (file->pos >= file->nbytes)
		{
			/*
			 * In the data_encrypted case, curOffset should always stay at
			 * BLCKSZ boundary.
			 */
			Assert(file->curOffset % BLCKSZ == 0 || !data_encrypted);

			/*
			 * Try to load more data into the buffer.
			 *
			 * In an encrypted file we should only advance if the current
			 * block is not the last one in the file. Otherwise, we might skip
			 * unused space in the block and the next write would create a
			 * hole.
			 */
			if (!data_encrypted || !BufFileLastBlock(file, numSegments))
			{
				if (!data_encrypted)
					file->curOffset += file->pos;
				else
					file->curOffset += BLCKSZ;
				file->pos = !data_encrypted ? 0 : SizeOfBufFilePageHeader;

				if (!is_transient)
					BufFileLoadBuffer((BufFile *) file);
				else
					BufFileLoadBufferTransient((TransientBufFile *) file);

				if (BUFFER_IS_EMPTY(file))
					break;		/* no more data available */
			}
			else
			{
				/*
				 * Last block of an encrypted file. Now that we've ran out of
				 * this block's data, there's no more data available.
				 */
				break;
			}
		}

		nthistime = file->nbytes - file->pos;

		if (nthistime > size)
			nthistime = size;
		Assert(nthistime > 0);

		memcpy(ptr, file->buffer.data + file->pos, nthistime);

		file->pos += nthistime;
		ptr = (void *) ((char *) ptr + nthistime);
		size -= nthistime;
		nread += nthistime;
	}

	return nread;
}

/*
 * BufFileWriteCommon
 *
 * Functionality needed by both BufFileWrite() and BufFileWriteTransient().
 */
static size_t
BufFileWriteCommon(BufFileCommon *file, void *ptr, size_t size,
				   bool is_transient)
{
	size_t		nwritten = 0;
	size_t		nthistime;
	bool		last_in_seg = false;

	Assert(!file->readOnly);

	while (size > 0)
	{
		if (file->pos >= BLCKSZ || last_in_seg)
		{
			/* Buffer full, dump it out */
			if (file->dirty)
			{
				if (!is_transient)
				{
					if (!data_encrypted)
						BufFileDumpBuffer((BufFile *)file);
					else
					{
#ifdef USE_ASSERT_CHECKING
						int	fileno = file->curFile;
#endif
						int	off = file->curOffset;

						BufFileDumpBufferEncrypted((BufFile *) file,
												   last_in_seg);
						last_in_seg = false;

						/*
						 * If overwriting, load the next buffer first. Since
						 * (unlike the unencrypted case) we only dump the
						 * whole buffers so w/o the load the next dump could
						 * overwrite even the part of the file that should
						 * stay unchanged.
						 */
						if (!file->append && file->curOffset != off)
						{
							/*
							 * curOffset must have advanced to the next block,
							 * possibly in the next segment file.
							 */
							Assert(file->curOffset == (off + BLCKSZ) ||
								   ((file->curFile == (fileno + 1)) &&
									file->curOffset == BLCKSZ));

							BufFileLoadBuffer((BufFile *) file);
						}
					}
				}
				else
					BufFileDumpBufferTransient((TransientBufFile *) file);
			}
			else
			{
				/* Hmm, went directly from reading to writing? */
				Assert(!last_in_seg);
				Assert(file->pos == BLCKSZ);

				file->curOffset += file->pos;
				if (!data_encrypted)
					file->pos = file->nbytes = 0;
				else
				{
					if (!is_transient)
					{
						/*
						 * Load the next buffer so that we don't corrupt the
						 * existing contents.
						 */
						file->pos = SizeOfBufFilePageHeader;
						BufFileLoadBuffer((BufFile *) file);
					}
					else
					{
						/*
						 * For transient file we can get here if an existing
						 * file was opened for writing in append mode.
						 */
						file->pos = file->nbytes = SizeOfBufFilePageHeader;
					}
				}
			}

			/*
			 * If curOffset changed above, it should still meet the assumption
			 * that buffer is the I/O unit for encrypted data.
			 */
			Assert(file->curOffset % BLCKSZ == 0 || !data_encrypted);
		}

		nthistime = BLCKSZ - file->pos;
		if (nthistime > size)
			nthistime = size;
		Assert(nthistime > 0);

		/*
		 * Close the segment if its last logical block ends here. (Transient
		 * files consist of a single segment so this is not relevant).
		 */
		if (data_encrypted && !is_transient)
		{
			off_t	next_off;

			/*
			 * If curFile hasn't been incremented yet, curOffset may still be
			 * beyond the end of the last dumped buffer. Therefore use modulo.
			 */
			next_off = file->curOffset % BYTES_PER_SEGMENT + file->pos;

			/*
			 * buffile_max_filesize should accommodate exactly
			 * BYTES_PER_SEGMENT_LOGICAL bytes of payload. Do not try to write
			 * more into the segment even if part of the last block stays
			 * unused.
			 */
			if (next_off + nthistime > buffile_max_filesize)
			{
				nthistime = buffile_max_filesize - next_off;
				last_in_seg = true;

				/*
				 * If buffile_max_filesize bytes are already there, flush the
				 * buffer immediately, or just advance to the next one if
				 * already flushed.
				 */
				if (nthistime == 0)
				{
					if (file->dirty)
						/* BufFileDumpBufferEncrypted will do the rest. */
						continue;
					else
					{
						file->curOffset += BLCKSZ;
						file->pos = file->nbytes = SizeOfBufFilePageHeader;
						/* The problem of the last block is solved now. */
						last_in_seg = false;
						/*
						 * Load the existing contents of the next buffer so
						 * that the next flush does not corrupt it.
						 */
						BufFileLoadBuffer((BufFile *) file);
					}
				}
			}
		}

		memcpy(file->buffer.data + file->pos, ptr, nthistime);

		file->dirty = true;
		file->pos += nthistime;
		if (file->nbytes < file->pos)
			file->nbytes = file->pos;

		ptr = (void *) ((char *) ptr + nthistime);
		size -= nthistime;
		nwritten += nthistime;
	}

	return nwritten;
}

/*
 * Retrieve the BufFilePageHeader.nbytes field from the page of 'segment' file
 * which starts at 'offset'. The whole page we get the information from will
 * end up in the memory pointed to by 'buffer'.
 */
static int16
BufFileGetUsefulBytes(File segment, off_t offset, PGAlignedBlock *buffer)
{
	BufFilePageHeader	*hdr;
	char	*data = buffer->data;

	/* Encrypted file is flushed one buffer at a time. */
	Assert(offset % BLCKSZ == 0);

	/*
	 * Read the information on bytes used in the last page of the
	 * segment.
	 */
	if (FileRead(segment,
				 data,
				 BLCKSZ,
				 offset,
				 WAIT_EVENT_BUFFILE_READ) != sizeof(*buffer))
		ereport(ERROR,
				(errcode_for_file_access(),
				 errmsg("could not read the page from BufFile \"%s\" at offset %zu: %m",
						FilePathName(segment), offset)));;

	/* Get the number of useful bytes in the last buffer. */
	hdr = (BufFilePageHeader *) buffer;
	decrypt_block(data + TWEAK_SIZE,
				  data + TWEAK_SIZE,
				  BLCKSZ - TWEAK_SIZE,
				  hdr->tweak,
				  InvalidBlockNumber,
				  EDK_BUFFILE);

	return hdr->nbytes;
}

/*
 * After the buffer has been loaded, adjust the usage info if trailing part is
 * actually not used. The point is that BLCKSZ bytes is always written if the
 * file is encrypted.
 *
 * 'segments' is an array of file segments, or NULL for a transient file.
 */
static void
BufFileAdjustUsefulBytes(BufFileCommon *file, BufFileSegment *segments)
{
	BufFilePageHeader	*hdr;
	bool is_transient = segments == NULL;

	/* This function is only need for encrypted files. */
	Assert(data_encrypted);

	/*
	 * Only the whole blocks are written/read in the data_encrypted case.
	 */
	Assert(file->nbytes % BLCKSZ == 0);

	if (file->nbytes == 0)
	{
		/* Maintain the convention that nbytes accounts for the header. */
		file->nbytes = SizeOfBufFilePageHeader;

		/*
		 * If the caller couldn't read any data, we should erase the existing
		 * contents. We might be past the end of the file due to seek now, and
		 * therefore the next write is not guaranteed to overwrite the leading
		 * part of the buffer.
		 */
		memset(file->buffer.data + file->nbytes, 0, BLCKSZ - file->nbytes);
	}
	else if (!is_transient && IsAllZero(file->buffer.data, BLCKSZ))
	{
		/*
		 * Looks like a hole due to lseek() - user should really see zeroes,
		 * so do not lower file->nbytes. This should not happen to a transient
		 * file as it does not support lseek().
		 */
	}
	else
	{
		/* Decrypt the buffer. */
		hdr = (BufFilePageHeader *) file->buffer.data;
		decrypt_block(file->buffer.data + TWEAK_SIZE,
					  file->buffer.data + TWEAK_SIZE,
					  BLCKSZ - TWEAK_SIZE,
					  hdr->tweak,
					  InvalidBlockNumber,
					  EDK_BUFFILE);

		/* Isn't the header corrupt? */
		Assert(hdr->nbytes <= file->nbytes);
		Assert(hdr->nbytes >= SizeOfBufFilePageHeader);

		/* Adjust the usage information if needed. */
		if (hdr->nbytes < file->nbytes)
		{
			if (!is_transient)
			{
				uint64	seg_size;

				/* Check the size of the current physical file. */
				seg_size = BufFileSegmentSize(&segments[file->curFile]);

				/* Is the current buffer at the end of the segment file? */
				if (file->curOffset + BLCKSZ < seg_size)
				{
					/*
					 * Not at the end, so it should be a hole created by
					 * lseek(). All the data beyond hdr->nbytes should be
					 * zeroes.
					 */
					MemSet(file->buffer.data + hdr->nbytes, 0,
						   BLCKSZ - hdr->nbytes);

					/*
					 * The zeroes should be available to the user, so do not
					 * lower file->nbytes.
					 */
				}
				else
				{
					Assert(file->curOffset + BLCKSZ == seg_size);

					/*
					 * We're at the end of the segment. Data beyond
					 * hdr->nbytes should only be padding up to BLCKSZ.
					 */
					file->nbytes = hdr->nbytes;
				}
			}
			else
			{
				/*
				 * There's no lseek for transient files, so there should be no
				 * holes in it. Thus we should be at the end of the file.
				 */
				file->nbytes = hdr->nbytes;
			}
		}
	}
}

/*
 * Truncate a BufFile created by BufFileCreateShared up to the given fileno and
 * the offset.
 */
void
BufFileTruncateShared(BufFile *file, int fileno, off_t offset)
{
	int			numFiles = file->numFiles;
	int			newFile;
	off_t		newOffset;
	char		segment_name[MAXPGPATH];
	int			i;

	if (data_encrypted)
	{
		off_t	pos_log, pos_phys;

		/*
		 * The caller thinks that all BLCKSZ bytes in the block are usable for
		 * the data, so compute the real position in our file in which each
		 * page contains some metadata (BufFilePageHeader).
		 */
		pos_log = fileno * BYTES_PER_SEGMENT_LOGICAL + offset;
		pos_phys = BufFileLogicalToPhysicalPos(pos_log);

		fileno = pos_phys / BYTES_PER_SEGMENT;
		offset = pos_phys % BYTES_PER_SEGMENT;
	}

	newFile = fileno;
	newOffset = file->common.curOffset;

	/*
	 * Loop over all the files up to the given fileno and remove the files
	 * that are greater than the fileno and truncate the given file up to the
	 * offset. Note that we also remove the given fileno if the offset is 0
	 * provided it is not the first file in which we truncate it.
	 */
	for (i = file->numFiles - 1; i >= fileno; i--)
	{
		if ((i != fileno || offset == 0) && i != 0)
		{
			SharedSegmentName(segment_name, file->name, i);
			FileClose(file->files[i].vfd);
			if (!SharedFileSetDelete(file->fileset, segment_name, true))
				ereport(ERROR,
						(errcode_for_file_access(),
						 errmsg("could not delete shared fileset \"%s\": %m",
								segment_name)));
			numFiles--;
			newOffset = BYTES_PER_SEGMENT;

			/*
			 * This is required to indicate that we have deleted the given
			 * fileno.
			 */
			if (i == fileno)
				newFile--;
		}
		else
		{
			if (!data_encrypted)
			{
				if (FileTruncate(file->files[i].vfd, offset,
								 WAIT_EVENT_BUFFILE_TRUNCATE) < 0)
					ereport(ERROR,
							(errcode_for_file_access(),
							 errmsg("could not truncate file \"%s\": %m",
									FilePathName(file->files[i].vfd))));
				file->files[i].size = offset;
			}
			else
			{
				off_t	offset_phys;
				BufFileSegment	*thisfile = &file->files[i];

				/* Encrypted file can only be truncated at block boundary. */
				if (offset % BLCKSZ == 0)
					offset_phys = offset;
				else
					offset_phys = offset - offset % BLCKSZ + BLCKSZ;

				if (FileTruncate(thisfile->vfd, offset_phys,
								 WAIT_EVENT_BUFFILE_TRUNCATE) < 0)
					ereport(ERROR,
							(errcode_for_file_access(),
							 errmsg("could not truncate file \"%s\": %m",
									FilePathName(thisfile->vfd))));
				thisfile->size = offset_phys;

				/*
				 * If only part of the last page should remain valid, update
				 * the page header.
				 */
				if (offset_phys != offset)
				{
					PGAlignedBlock	buffer;
					int		nbytes;
					off_t	off_page = offset - offset % BLCKSZ;
					int	nbytes_new = offset % BLCKSZ;

					nbytes = BufFileGetUsefulBytes(thisfile->vfd, off_page,
												   &buffer);
					if (nbytes_new < nbytes)
					{
						BufFilePageHeader	*hdr;
						int	written;

						/*
						 * Update the header, encrypt the page again and write
						 * it.
						 */
						hdr = (BufFilePageHeader *) buffer.data;
						hdr->nbytes = nbytes_new;
						encrypt_block(buffer.data + TWEAK_SIZE,
									  buffer.data + TWEAK_SIZE,
									  BLCKSZ - TWEAK_SIZE,
									  hdr->tweak,
									  InvalidXLogRecPtr,
									  InvalidBlockNumber,
									  EDK_BUFFILE);
						written = FileWrite(thisfile->vfd,
											buffer.data,
											BLCKSZ,
											off_page,
											WAIT_EVENT_BUFFILE_WRITE);
						if (written <= 0 || written != BLCKSZ)
							ereport(ERROR,
									(errcode_for_file_access(),
									 errmsg("could not write to file \"%s\": %m",
											FilePathName(thisfile->vfd))));
					}
					else if (nbytes_new >= nbytes)
						ereport(ERROR,
								(errmsg("could not truncate file \"%s\", it's already smaller than the requested size",
										FilePathName(thisfile->vfd))));
				}
			}
			newOffset = offset;
		}
	}

	file->numFiles = numFiles;

	/*
	 * If the truncate point is within existing buffer then we can just adjust
	 * pos within buffer.
	 */
	if (newFile == file->common.curFile &&
		newOffset >= file->common.curOffset &&
		newOffset <= file->common.curOffset + file->common.nbytes)
	{
		/* No need to reset the current pos if the new pos is greater. */
		if (newOffset <= file->common.curOffset + file->common.pos)
			file->common.pos = (int) (newOffset - file->common.curOffset);

		/* Adjust the nbytes for the current buffer. */
		file->common.nbytes = (int) (newOffset - file->common.curOffset);
	}
	else if (newFile == file->common.curFile &&
			 newOffset < file->common.curOffset)
	{
		/*
		 * The truncate point is within the existing file but prior to the
		 * current position, so we can forget the current buffer and reset the
		 * current position.
		 */
		if (!data_encrypted)
		{
			file->common.curOffset = newOffset;
			file->common.pos = 0;
			file->common.nbytes = 0;
		}
		else
		{
			/* Encrypted buffer must start at block boundary. */
			file->common.pos = newOffset % BLCKSZ;
			file->common.curOffset = newOffset - file->common.pos;

			/*
			 * Unlike the unencrypted code path, which allows the buffer to
			 * start anywhere, caller might need some valid data at the
			 * beginning of the buffer because the buffer has to start at
			 * block boundary.
			 */
			BufFileLoadBuffer(file);
			/* Now we have a clean buffer for sure. */
			file->common.dirty = false;
		}
	}
	else if (newFile < file->common.curFile)
	{
		/*
		 * The truncate point is prior to the current file, so need to reset
		 * the current position accordingly.
		 */
		file->common.curFile = newFile;

		if (!data_encrypted)
		{
			file->common.curOffset = newOffset;
			file->common.pos = 0;
			file->common.nbytes = 0;
		}
		else
		{
			/* See above. */
			file->common.pos = newOffset % BLCKSZ;
			file->common.curOffset = newOffset - file->common.pos;
			BufFileLoadBuffer(file);
			file->common.dirty = false;
		}
	}
	/* Nothing to do, if the truncate point is beyond current file. */
}
