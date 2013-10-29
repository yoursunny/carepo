/**
 * @file sync/SyncUtil.h
 *  
 * Part of NDNx Sync.
 *
 * Portions Copyright (C) 2013 Regents of the University of California.
 * 
 * Based on the CCNx C Library by PARC.
 * Copyright (C) 2011 Palo Alto Research Center, Inc.
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation.
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details. You should have received
 * a copy of the GNU Lesser General Public License along with this library;
 * if not, write to the Free Software Foundation, Inc., 51 Franklin Street,
 * Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef NDN_SyncUtil
#define NDN_SyncUtil

#include "IndexSorter.h"
#include <ndn/ndn.h>

struct SyncLongHashStruct;
struct SyncRootStruct;
struct SyncBaseStruct;

// emit a message to stderr
void
SyncNoteErr(const char *msg);

int
SyncSetDecodeErr(struct ndn_buf_decoder *d, int val);

int
SyncCheckDecodeErr(struct ndn_buf_decoder *d);


//// Elapsed high-precision time

// get current time in microseconds (since arbitrary event)
int64_t
SyncCurrentTime(void);

// get delta time in microseconds (from mt1 to mt2)
int64_t
SyncDeltaTime(int64_t mt1, int64_t mt2);

// Some basic ndn_charbuf utilities

struct ndn_buf_decoder *
SyncInitDecoderFromCharbufRange(struct ndn_buf_decoder *d,
                                const struct ndn_charbuf *cb,
                                ssize_t start, ssize_t stop);

struct ndn_buf_decoder *
SyncInitDecoderFromCharbuf(struct ndn_buf_decoder *d,
                           const struct ndn_charbuf *cb,
                           ssize_t start);

// for a hex encoding character, returns a a 4-bit unsigned number
// otherwise returns -1
int
SyncDecodeHexDigit(char c);

// for a valid URI character, returns the code for the character
// otherwise returns -1
int
SyncDecodeUriChar(char c);

char *
SyncHexStr(const unsigned char *cp, size_t sz);

/////////////////////////////////////////////////////////////////
// Routines for root-relative reporting.
/////////////////////////////////////////////////////////////////

int
SyncNoteFailed(struct SyncRootStruct *root, char *where, char *why, int line);

void
SyncNoteSimple(struct SyncRootStruct *root, char *where, char *s1);

void
SyncNoteSimple2(struct SyncRootStruct *root, char *where, char *s1, char *s2);

void
SyncNoteSimple3(struct SyncRootStruct *root, char *where, char *s1, char *s2, char *s3);

void
SyncNoteUri(struct SyncRootStruct *root, char *where, char *why, struct ndn_charbuf *name);

void
SyncNoteUriBase(struct SyncBaseStruct *base, char *where, char *why, struct ndn_charbuf *name);

/////////////////////////////////////////////////////////////////
// Routines for dealing with names.
/////////////////////////////////////////////////////////////////

/**
 * compare two names
 * advances both decoders, but early exit may leave them not fully over the names
 * decoder error flags may be useful, though, if any errors occur
 */
int
SyncCmpNamesInner(struct ndn_buf_decoder *xx, struct ndn_buf_decoder *yy);

/**
 * compare two names
 * @returns >1 if cbx > cby, 0 if cby == cby, <-1 if cbx < cby
 * @returns BAD_CMP for a parsing error
 */
#define SYNC_BAD_CMP (-2)
int
SyncCmpNames(const struct ndn_charbuf *cbx, const struct ndn_charbuf *cby);

/**
 * tests to see if charbuf refers to a name
 * @returns 1 for a name, 0 otherwise
 */
int
SyncIsName(const struct ndn_charbuf *cb);

/**
 * @returns number of components in the name
 */
int
SyncComponentCount(const struct ndn_charbuf *name);

/**
 * simple pattern matching, where the pattern may contain components with
 * a single 255 byte to match a single name component
 * @returns number of matching components in the pattern if the name
 * (starting at component index start) matches the prefix,
 * @returns -1 if there is a parsing error or no match
 */
int
SyncPatternMatch(const struct ndn_charbuf *pattern,
                 const struct ndn_charbuf *name,
                 int start);

/**
 * @returns number of components in the prefix if the name
 * (starting at component index start) matches the prefix,
 * @returns -1 if there is a parsing error or no match
 */
int
SyncPrefixMatch(const struct ndn_charbuf *prefix,
                const struct ndn_charbuf *name,
                int start);

/**
 * @returns number of components in the longest prefix of both x and y
 * @returns -1 if there is a parsing error
 */
int
SyncComponentMatch(const struct ndn_charbuf *x,
                   const struct ndn_charbuf *y);

/**
 * finds the bytes for a component (not including the tag)
 * src must be a name, comp the component index
 * @returns < 0 for an error, 0 otherwise
 */
int
SyncGetComponentPtr(const struct ndn_charbuf *src, int comp,
                    const unsigned char **xp, ssize_t *xs);

/**
 * appends components from src to dst (both must be names)
 * @returns < 0 for an error
 * @returns the number of components copied otherwise
 */
int
SyncAppendAllComponents(struct ndn_charbuf *dst,
                        const struct ndn_charbuf *src);

/**
 * Convenience routine to make a name from a ndn_indexbuf.
 * The storage for the returned charbuf is owned by the caller.
 * @returns a charbuf for the name (NULL if an error)
 */
struct ndn_charbuf *
SyncNameForIndexbuf(const unsigned char *buf, struct ndn_indexbuf *comps);

/**
 * Convenience routine to make a uri for a name.
 * The storage for the returned charbuf is owned by the caller.
 * @returns the charbuf with the uri for the name (NULL if an error)
 */
struct ndn_charbuf *
SyncUriForName(struct ndn_charbuf *name);

/**
 * Convenience routine to make a Sync protocol command prefix for a marker.
 * The returned name includes the topo prefix, the marker, and the slice hash.
 * The storage for the returned charbuf is owned by the caller.
 * @returns the charbuf with the uri for the name (NULL if an error)
 */
struct ndn_charbuf *
SyncConstructCommandPrefix(struct SyncRootStruct *root, char *marker);

/////////////////////////////////////////////////////////////////
// Routines for dealing with hashes.
/////////////////////////////////////////////////////////////////


struct SyncHashInfoList {
    struct SyncHashInfoList *next;
    struct SyncHashCacheEntry *ce;
    int64_t lastSeen;
    int64_t lastReplied;
};

/**
 * finds the hash code, storing the pointer to *xp and the length to *xs
 * if the hash is valid (test for *xs != 0 to be sure)
 * a hash code may be a ContentHash, or the last component of a Name
 * (for convenience, a Component may also be used)
 * non-destructive to the decoder
 * no error codes, but a pointer is set only for valid cases
 */
void
SyncGetHashPtr(const struct ndn_buf_decoder *hd,
               const unsigned char **xp, ssize_t *xs);

/**
 * compares two hash codes in charbufs
 * @returns < 0 for X < Y, 0 for X = Y, > 0 for X > Y
 */
int
SyncCmpHashesRaw(const unsigned char *xp, ssize_t xs,
                 const unsigned char *yp, ssize_t ys);

/**
 * compares two hash codes in charbufs
 * @returns < 0 for X < Y, 0 for X = Y, > 0 for X > Y
 */
int
SyncCompareHash(struct ndn_charbuf *hashX, struct ndn_charbuf *hashY);


// accumulates a simple hash code into the hash accumulator
// hash code is raw bytes
void
SyncAccumHashRaw(struct SyncLongHashStruct *hp,
                 const unsigned char *xp, size_t xs);

// accumulates a simple hash code referenced by a decoder
// into the hash accumulator for the composite node
// non-destructive of decoder
void
SyncAccumHashInner(struct SyncLongHashStruct *hp,
                   const struct ndn_buf_decoder *d);

// accumulates a simple hash code referenced by a decoder
// into the hash accumulator for the composite node
// non-destructive of decoder
void
SyncAccumHash(struct SyncLongHashStruct *hp, const struct ndn_charbuf *cb);

// convert long hash to charbuf
struct ndn_charbuf *
SyncLongHashToBuf(const struct SyncLongHashStruct *hp);

// makes a small, unsigned hash code from a full hash
// useful to speed up hash table lookups
uint32_t
SyncSmallHash(const unsigned char * xp, ssize_t xs);

// maintains a hash info list, sorted by most recent first (lastSeen)
struct SyncHashInfoList *
SyncNoteHash(struct SyncHashInfoList *head, struct SyncHashCacheEntry *ce);

// accumulates exceptions from list into acc
// acc == NULL
// returns new accum, not sorted
struct SyncNameAccum *
SyncExclusionsFromHashList(struct SyncRootStruct *root,
                           struct SyncNameAccum *acc,
                           struct SyncHashInfoList *list);

/////////////////////////////////////////////////////////////////
// Routines for appending numbers, hashes and names to a charbuf.
/////////////////////////////////////////////////////////////////

// appends a dtag and an unsigned number
int
SyncAppendTaggedNumber(struct ndn_charbuf *cb,
                       enum ndn_dtag dtag,
                       unsigned val);

// appends a sequence of random bytes
int
SyncAppendRandomBytes(struct ndn_charbuf *cb, int n);

// appends a random hash code as a ContentHash
int
SyncAppendRandomHash(struct ndn_charbuf *cb, int n);

// appends a random name of nComp random-length components plus a random hash
int
SyncAppendRandomName(struct ndn_charbuf *cb, int nComp, int maxCompLen);

// appendElementInner appends the ndnb encoding from the decoder to the cb output
// types supported: NDN_DTAG_Name, NDN_DTAG_SyncContentHash, NDN_DTAG_BinaryValue
// any error returns < 0
// this routine advances the decoder!
int
SyncAppendElementInner(struct ndn_charbuf *cb, struct ndn_buf_decoder *d);

// appendElement appends the ndnb encoding from the src to the dst
// types supported: NDN_DTAG_Name, NDN_DTAG_SyncContentHash, NDN_DTAG_BinaryValue
// any error returns < 0
int
SyncAppendElement(struct ndn_charbuf *dst, const struct ndn_charbuf *src);

struct ndn_charbuf *
SyncExtractName(struct ndn_buf_decoder *d);

struct ndn_charbuf *
SyncCopyName(const struct ndn_charbuf *name);

///////////////////////////////////////////////////////
// Routines for simple parsing
///////////////////////////////////////////////////////

unsigned
SyncParseUnsigned(struct ndn_buf_decoder *d, enum ndn_dtag dtag);

ssize_t
SyncParseHash(struct ndn_buf_decoder *d);

ssize_t
SyncParseName(struct ndn_buf_decoder *d);

////////////////////////////////////////
// Name and Node Accumulators
////////////////////////////////////////

struct SyncNameAccumEntry {
    struct ndn_charbuf *name;
    intmax_t data;
};

struct SyncNameAccum {
    int len;
    int lim;
    struct SyncNameAccumEntry *ents;
};

struct SyncNameAccumList {
    struct SyncNameAccumList *next;
    struct SyncNameAccum *accum;
};

/**
 * @returns a new name accum with at least lim space for names
 */
struct SyncNameAccum *
SyncAllocNameAccum(int lim);

/**
 * frees the name accum, but not the names
 * @returns NULL
 */
struct SyncNameAccum *
SyncFreeNameAccum(struct SyncNameAccum *na);

/**
 * frees the name accum and all of the names
 * @returns NULL
 */
struct SyncNameAccum *
SyncFreeNameAccumAndNames(struct SyncNameAccum *na);

/**
 * default sorter callback for a name accum
 * uses NDN standard name order
 */
int
SyncNameAccumSorter(IndexSorter_Base base,
                    IndexSorter_Index x, IndexSorter_Index y);

/**
 * appends a new name with associated data
 * important: the name is not copied!
 */
int
SyncNameAccumAppend(struct SyncNameAccum *na,
                    struct ndn_charbuf *name,
                    intmax_t data);

/**
 * canonicalizes a name with respect to the given name accum
 * should be used for relatively small canon sets
 * @returns an equal name if it was in the accum
 * @returns a copy of the name (and enters it) if no equal name was in the accum
 */
struct ndn_charbuf *
SyncNameAccumCanon(struct SyncNameAccum *na,
                   const struct ndn_charbuf *name);

struct SyncNodeAccum {
    int len;
    int lim;
    struct SyncNodeComposite **ents;
};

struct SyncNodeAccum *
SyncAllocNodeAccum(int lim);

struct SyncNodeAccum *
SyncFreeNodeAccum(struct SyncNodeAccum *na);

void
SyncAccumNode(struct SyncNodeAccum *na, struct SyncNodeComposite *nc);

/**
 * Adds the given name to any applicable roots.
 * Use seq_num == 0 to ignore sequence number.
 * @returns < 0 for failure, number of additions to roots for success.
 */
int
SyncAddName(struct SyncBaseStruct *base, struct ndn_charbuf *name, uint64_t seq_num);

/**
 * takes a list of names and sort them, removing duplicates
 * names are transfered to the return accum, so src is left empty
 * @returns an accum with the sorted names
 */
extern struct SyncNameAccum *
SyncSortNames(struct SyncRootStruct *root, struct SyncNameAccum *src);


///////////////////////////////////////////////////////
// Routines for simple interest creation
///////////////////////////////////////////////////////

/**
 * given a spec for the desired fields
 * (scope, lifetime, maxSuffix, child are omitted if negative)
 * @returns the encoding for an interest
 */
struct ndn_charbuf *
SyncGenInterest(struct ndn_charbuf *name,
                int scope,
                int lifetime,
                int maxSuffix,
                int childPref,
                struct SyncNameAccum *excl);

///////////////////////////////////////////////////////
// Routines for local repo read/write
///////////////////////////////////////////////////////

/**
 * given a sync node hash,
 * @returns the local repo name for the node
 */
struct ndn_charbuf *
SyncNameForLocalNode(struct SyncRootStruct *root, struct ndn_charbuf *hash);

/**
 * given a charbuf cb for a content object, with optional parsing offsets in pco,
 * sets *xp and *xs with the pointer and length of the actual content bytes
 * @returns < 0 for failure
 */
int
SyncPointerToContent(struct ndn_charbuf *cb, struct ndn_parsed_ContentObject *pco,
                     const unsigned char **xp, size_t *xs);


/**
 * given a charbuf cb and name for a content object, signs the bytes and
 * @returns the signed buffer (NULL for failure)
 */
struct ndn_charbuf *
SyncSignBuf(struct SyncBaseStruct *base,
            struct ndn_charbuf *cb,
            struct ndn_charbuf *name,
            long fresh, int flags);


/**
 * given a local repo name and a buffer to fill,
 * fills cb with the content object (note: not the content itself)
 * pco is filled as a useful side effect, but may be NULL
 * @returns < 0 if the node fails
 */
int
SyncLocalRepoFetch(struct SyncBaseStruct *base,
                   struct ndn_charbuf *name,
                   struct ndn_charbuf *cb,
                   struct ndn_parsed_ContentObject *pco);


/**
 * given a sync node hash,
 * @returns the local repo name for the node
 */
int
SyncLocalRepoStore(struct SyncBaseStruct *base,
                   struct ndn_charbuf *name,
                   struct ndn_charbuf *content,
                   int flags);

#endif

