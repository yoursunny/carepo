/**
 * @file sync/SyncUtil.c
 *  
 * Part of NDNx Sync.
 */
/*
 * Portions Copyright (C) 2013 Regents of the University of California.
 * 
 * Based on the CCNx C Library by PARC.
 * Copyright (C) 2011-2012 Palo Alto Research Center, Inc.
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

#include "SyncBase.h"
#include "SyncHashCache.h"
#include "SyncNode.h"
#include "SyncPrivate.h"
#include "SyncRoot.h"
#include "SyncUtil.h"
#include "IndexSorter.h"
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/time.h>
//#include <ndnr/ndnr_sync.h>
#include <ndn/ndn.h>
#include <ndn/charbuf.h>
#include <ndn/coding.h>
#include <ndn/indexbuf.h>
#include <ndn/loglevels.h>
#include <ndn/uri.h>


static int freshLimit = 30;             // freshness limit, in seconds

// external utilities

#define SET_ERR(d) SyncSetDecodeErr(d, -__LINE__)
extern void
SyncNoteErr(const char *msg) {
    char *s = getenv("NDNS_NOTE_ERR");
    int useStdErr = 0;
    if (s != NULL && s[0] != 0)
        useStdErr = strtol(s, NULL, 10);
    if (useStdErr > 0) {
        fprintf(stderr, "**** error in %s\n", msg);
        fflush(stderr);
    }
}

extern int
SyncSetDecodeErr(struct ndn_buf_decoder *d, int val) {
    SyncNoteErr("setErr");
    if (d->decoder.state >= 0) d->decoder.state = val;
    return val;
}

extern int
SyncCheckDecodeErr(struct ndn_buf_decoder *d) {
    return d->decoder.state < 0;
}

extern int64_t
SyncCurrentTime(void) {
    const int64_t M = 1000*1000;
    struct timeval now = {0};
    gettimeofday(&now, 0);
    return now.tv_sec*M+now.tv_usec;
}

extern int64_t
SyncDeltaTime(int64_t mt1, int64_t mt2) {
    return mt2-mt1;
}

extern struct ndn_buf_decoder *
SyncInitDecoderFromCharbufRange(struct ndn_buf_decoder *d,
                                const struct ndn_charbuf *cb,
                                ssize_t start, ssize_t stop) {
    if (((size_t) stop) >  cb->length) stop = cb->length;
    if (start < 0 || start > stop) {
        SET_ERR(d); // invalid
    } else {
        ndn_buf_decoder_start(d, cb->buf+start, stop - start);
    }
    d->decoder.nest = 1;
    return d;
}

extern struct ndn_buf_decoder *
SyncInitDecoderFromCharbuf(struct ndn_buf_decoder *d,
                           const struct ndn_charbuf *cb,
                           ssize_t start) {
    return SyncInitDecoderFromCharbufRange(d, cb, start, cb->length);
}

extern int
SyncDecodeHexDigit(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return 10 + c - 'a';
    if (c >= 'A' && c <= 'F') return 10 + c - 'A';
    return -1;
}

extern int
SyncDecodeUriChar(char c) {
    if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
        || (c >= '0' && c <= '9')
        || c == '/' || c == '%' || c == ':'
        || c == '.' || c == '-' || c == '_' || c == '~') {
        // valid character
        return c;
    }
    return -1;
}

extern char *
SyncHexStr(const unsigned char *cp, size_t sz) {
    char *hex = NEW_ANY(sz*2+1, char);
    char *hexLit = "0123456789abcdef";
    int i = 0;
    for (i = 0; i < sz; i++) {
        hex[i+i] = hexLit[(cp[i] / 16) & 15];
        hex[i+i+1] = hexLit[cp[i] & 15];
    }
    return hex;
}

/////////////////////////////////////////////////////////////////
// Routines for root-relative reporting.
/////////////////////////////////////////////////////////////////

extern int
SyncNoteFailed(struct SyncRootStruct *root, char *where, char *why, int line) {
    if (root->base->debug >= NDNL_SEVERE)
        sync_msg(root->base, "%s, root#%u, failed, %s, line %d",
                 where, root->rootId, why, line);
    SyncNoteErr("Sync.SyncNoteFailed");
    return -line;
}

extern void
SyncNoteSimple(struct SyncRootStruct *root, char *where, char *s1) {
    sync_msg(root->base, "%s, root#%u, %s", where, root->rootId, s1);
}

extern void
SyncNoteSimple2(struct SyncRootStruct *root, char *where, char *s1, char *s2) {
    sync_msg(root->base, "%s, root#%u, %s, %s", where, root->rootId, s1, s2);
}

extern void
SyncNoteSimple3(struct SyncRootStruct *root, char *where, char *s1, char *s2, char *s3) {
    sync_msg(root->base, "%s, root#%u, %s, %s, %s", where, root->rootId, s1, s2, s3);
}

extern void
SyncNoteUri(struct SyncRootStruct *root, char *where, char *why, struct ndn_charbuf *name) {
    struct ndn_charbuf *uri = SyncUriForName(name);
    char *str = ndn_charbuf_as_string(uri);
    sync_msg(root->base, "%s, root#%u, %s, %s", where, root->rootId, why, str);
    ndn_charbuf_destroy(&uri);
}

extern void
SyncNoteUriBase(struct SyncBaseStruct *base, char *where, char *why, struct ndn_charbuf *name) {
    struct ndn_charbuf *uri = SyncUriForName(name);
    char *str = ndn_charbuf_as_string(uri);
    sync_msg(base, "%s, %s, %s", where, why, str);
    ndn_charbuf_destroy(&uri);
}

/////////////////////////////////////////////////////////////////
// Routines for dealing with names.
/////////////////////////////////////////////////////////////////

extern int
SyncCmpNamesInner(struct ndn_buf_decoder *xx, struct ndn_buf_decoder *yy) {
    // adapted from ndn_compare_names
    if (ndn_buf_match_dtag(xx, NDN_DTAG_Name))
        ndn_buf_advance(xx);
    else SET_ERR(xx);
    if (ndn_buf_match_dtag(yy, NDN_DTAG_Name))
        ndn_buf_advance(yy);
    else SET_ERR(yy);
    ssize_t cmp = 0;
    while (SyncCheckDecodeErr(xx) == 0 && SyncCheckDecodeErr(yy) == 0) {
        int more_x = ndn_buf_match_dtag(xx, NDN_DTAG_Component);
        int more_y = ndn_buf_match_dtag(yy, NDN_DTAG_Component);
        cmp = more_x - more_y;
        if (more_x == 0 || cmp != 0)
            break;
        ndn_buf_advance(xx);
        ndn_buf_advance(yy);
        size_t xs = 0;
        size_t ys = 0;
        const unsigned char *xp = NULL;
        const unsigned char *yp = NULL;
        if (ndn_buf_match_blob(xx, &xp, &xs)) ndn_buf_advance(xx);
        if (ndn_buf_match_blob(yy, &yp, &ys)) ndn_buf_advance(yy);
        cmp = xs - ys;
        if (cmp != 0)
            break;
        if (xs != 0) {
            cmp = memcmp(xp, yp, xs);
            if (cmp != 0)
                break;
        }
        ndn_buf_check_close(xx);
        ndn_buf_check_close(yy);
    }
    ndn_buf_check_close(xx);
    ndn_buf_check_close(yy);
    if (cmp > 0) return 1;
    if (cmp < 0) return -1;
    return 0;
}

extern int
SyncCmpNames(const struct ndn_charbuf *cbx, const struct ndn_charbuf *cby) {
    struct ndn_buf_decoder xds;
    struct ndn_buf_decoder *xx = SyncInitDecoderFromCharbuf(&xds, cbx, 0);
    struct ndn_buf_decoder yds;
    struct ndn_buf_decoder *yy = SyncInitDecoderFromCharbuf(&yds, cby, 0);
    int cmp = SyncCmpNamesInner(xx, yy);
    if (SyncCheckDecodeErr(xx) || SyncCheckDecodeErr(yy)) return SYNC_BAD_CMP;
    return (cmp);
}

// tests to see if the offset refers to a name
// no errors
extern int
SyncIsName(const struct ndn_charbuf *cb) {
    struct ndn_buf_decoder xds;
    struct ndn_buf_decoder *d = SyncInitDecoderFromCharbuf(&xds, cb, 0);
    if (!SyncCheckDecodeErr(d) && ndn_buf_match_dtag(d, NDN_DTAG_Name))
        return 1;
    return 0;
}

extern int
SyncComponentCount(const struct ndn_charbuf *name) {
    struct ndn_buf_decoder ds;
    struct ndn_buf_decoder *d = SyncInitDecoderFromCharbuf(&ds, name, 0);
    int count = 0;
    if (ndn_buf_match_dtag(d, NDN_DTAG_Name)) {
        ndn_buf_advance(d);
        while (ndn_buf_match_dtag(d, NDN_DTAG_Component)) {
            const unsigned char *cPtr = NULL;
            size_t cSize = 0;
            ndn_buf_advance(d);
            if (ndn_buf_match_blob(d, &cPtr, &cSize)) ndn_buf_advance(d);
            ndn_buf_check_close(d);
            count++;
        }
        ndn_buf_check_close(d);
        if (!SyncCheckDecodeErr(d))
            return count;
    }
    return -1;
}

extern int
SyncPatternMatch(const struct ndn_charbuf *pattern,
                 const struct ndn_charbuf *name,
                 int start) {
    struct ndn_buf_decoder xds;
    struct ndn_buf_decoder *xx = SyncInitDecoderFromCharbuf(&xds, pattern, 0);
    struct ndn_buf_decoder yds;
    struct ndn_buf_decoder *yy = SyncInitDecoderFromCharbuf(&yds, name, 0);
    if (!ndn_buf_match_dtag(xx, NDN_DTAG_Name)) return -1;
    ndn_buf_advance(xx);
    if (!ndn_buf_match_dtag(yy, NDN_DTAG_Name)) return -1;
    ndn_buf_advance(yy);
    int match = 0;
    int index = 0;
    while (index < start) {
        // skip initial components of name
        if (!ndn_buf_match_dtag(yy, NDN_DTAG_Component))
            return -1;
        ndn_buf_advance(yy);
        if (!ndn_buf_match_blob(yy, NULL, NULL))
            return -1;
        ndn_buf_advance(yy);
        ndn_buf_check_close(yy);
        index++;
    }
    while (SyncCheckDecodeErr(xx) == 0 && SyncCheckDecodeErr(yy) == 0) {
        int more_x = ndn_buf_match_dtag(xx, NDN_DTAG_Component);
        int more_y = ndn_buf_match_dtag(yy, NDN_DTAG_Component);
        if (more_x == 0) {
            // end of pattern
            ndn_buf_check_close(xx);
            if (!SyncCheckDecodeErr(xx))
                return match;
            return -1;
        }
        if (more_y == 0) {
            // end of name
            ndn_buf_check_close(yy);
            if (!SyncCheckDecodeErr(yy))
                return 0;
            return -1;
        }
        ndn_buf_advance(xx);
        ndn_buf_advance(yy);
        size_t xs = 0;
        size_t ys = 0;
        const unsigned char *xp = NULL;
        const unsigned char *yp = NULL;
        if (ndn_buf_match_blob(xx, &xp, &xs)) ndn_buf_advance(xx);
        if (ndn_buf_match_blob(yy, &yp, &ys)) ndn_buf_advance(yy);
        int star = 0;
        if (xs > 0 && (xp[0] == 255)) {
            // a component starting with FF may be a star-matcher
            // if not a single byte, swallow the FF
            xs--;
            xp++;
            if (xs == 0) star = 1;
        }
        if (star) {
            // star-matching
        } else if (xs != ys) {
            // name lengths differ
            return 0;
        } else {
            // equal sizes, check contents
            ssize_t cmp = memcmp(xp, yp, xs);
            if (cmp != 0) return 0;
        }
        match++;
        ndn_buf_check_close(xx);
        ndn_buf_check_close(yy);
    }
    return (-1);
}

extern int
SyncPrefixMatch(const struct ndn_charbuf *prefix,
                const struct ndn_charbuf *name,
                int start) {
    struct ndn_buf_decoder xds;
    struct ndn_buf_decoder *xx = SyncInitDecoderFromCharbuf(&xds, prefix, 0);
    struct ndn_buf_decoder yds;
    struct ndn_buf_decoder *yy = SyncInitDecoderFromCharbuf(&yds, name, 0);
    if (!ndn_buf_match_dtag(xx, NDN_DTAG_Name)) return -1;
    ndn_buf_advance(xx);
    if (!ndn_buf_match_dtag(yy, NDN_DTAG_Name)) return -1;
    ndn_buf_advance(yy);
    int match = 0;
    int index = 0;
    while (index < start) {
        // skip initial components of name
        if (!ndn_buf_match_dtag(yy, NDN_DTAG_Component)) break;
        ndn_buf_advance(yy);
        if (ndn_buf_match_blob(yy, NULL, NULL)) ndn_buf_advance(yy);
        index++;
    }
    while (SyncCheckDecodeErr(xx) == 0 && SyncCheckDecodeErr(yy) == 0) {
        int more_x = ndn_buf_match_dtag(xx, NDN_DTAG_Component);
        int more_y = ndn_buf_match_dtag(yy, NDN_DTAG_Component);
        if (more_x == 0) {
            // end of prefix
            ndn_buf_check_close(xx);
            if (!SyncCheckDecodeErr(xx))
                return match;
            return -1;
        }
        if (more_y == 0) {
            // end of name
            ndn_buf_check_close(yy);
            if (!SyncCheckDecodeErr(yy))
                return 0;
            return -1;
        }
        ndn_buf_advance(xx);
        ndn_buf_advance(yy);
        size_t xs = 0;
        size_t ys = 0;
        const unsigned char *xp = NULL;
        const unsigned char *yp = NULL;
        if (ndn_buf_match_blob(xx, &xp, &xs)) ndn_buf_advance(xx);
        if (ndn_buf_match_blob(yy, &yp, &ys)) ndn_buf_advance(yy);
        if (xs != ys) {
            // name lengths differ
            return 0;
        } else if (xs > 0) {
            // equal sizes, check contents
            ssize_t cmp = memcmp(xp, yp, xs);
            if (cmp != 0) return 0;
        }
        match++;
        ndn_buf_check_close(xx);
        ndn_buf_check_close(yy);
    }
    return -1;
}

extern int
SyncComponentMatch(const struct ndn_charbuf *x,
                   const struct ndn_charbuf *y) {
    struct ndn_buf_decoder xds;
    struct ndn_buf_decoder *xx = SyncInitDecoderFromCharbuf(&xds, x, 0);
    struct ndn_buf_decoder yds;
    struct ndn_buf_decoder *yy = SyncInitDecoderFromCharbuf(&yds, y, 0);
    if (!ndn_buf_match_dtag(xx, NDN_DTAG_Name)) return -1;
    ndn_buf_advance(xx);
    if (!ndn_buf_match_dtag(yy, NDN_DTAG_Name)) return -1;
    ndn_buf_advance(yy);
    int match = 0;
    size_t xs = 0;
    size_t ys = 0;
    const unsigned char *xp = NULL;
    const unsigned char *yp = NULL;
    for (;;) {
        if (!ndn_buf_match_dtag(xx, NDN_DTAG_Component)) break;
        if (!ndn_buf_match_dtag(yy, NDN_DTAG_Component)) break;
        ndn_buf_advance(xx);
        ndn_buf_advance(yy);
        if (!ndn_buf_match_blob(xx, &xp, &xs)) return -1;
        if (!ndn_buf_match_blob(yy, &yp, &ys)) return -1;
        if (xs != ys) break;
        ssize_t cmp = memcmp(xp, yp, xs);
        if (cmp != 0) break;
        ndn_buf_advance(xx);
        ndn_buf_advance(yy);
        ndn_buf_check_close(xx);
        ndn_buf_check_close(yy);
        match++;
    }
    if (SyncCheckDecodeErr(xx)) match = -1;
    if (SyncCheckDecodeErr(yy)) match = -1;
    return match;
}

extern int
SyncGetComponentPtr(const struct ndn_charbuf *src, int comp,
                    const unsigned char **xp, ssize_t *xs) {
    struct ndn_buf_decoder sbd;
    struct ndn_buf_decoder *s = SyncInitDecoderFromCharbuf(&sbd, src, 0);
    if (ndn_buf_match_dtag(s, NDN_DTAG_Name) && (xp != NULL) && (xs != NULL)) {
        int pos = 0;
        ndn_buf_advance(s);
        while (pos <= comp) {
            if (!ndn_buf_match_dtag(s, NDN_DTAG_Component)) break;
            ndn_buf_advance(s);
            if (!ndn_buf_match_blob(s, xp, (size_t *) xs)) break;
            ndn_buf_advance(s);
            ndn_buf_check_close(s);
            if (SyncCheckDecodeErr(s)) break;
            if (pos == comp)
                // found the component
                return 0;
            pos++;
        }
    }
    return -1;
}

extern int
SyncAppendAllComponents(struct ndn_charbuf *dst,
                        const struct ndn_charbuf *src) {
    struct ndn_buf_decoder sbd;
    struct ndn_buf_decoder *s = SyncInitDecoderFromCharbuf(&sbd, src, 0);
    int count = 0;
    int pos = 0;
    if (!ndn_buf_match_dtag(s, NDN_DTAG_Name))
        // src is not a name
        return -__LINE__;
    ndn_buf_advance(s);
    for (;;) {
        if (!ndn_buf_match_dtag(s, NDN_DTAG_Component)) break;
        ndn_buf_advance(s);
        const unsigned char *cPtr = NULL;
        size_t cSize = 0;
        if (ndn_buf_match_blob(s, &cPtr, &cSize)) ndn_buf_advance(s);
        if (ndn_name_append(dst, cPtr, cSize) < 0)
            return -__LINE__;
        count++;
        ndn_buf_check_close(s);
        if (SyncCheckDecodeErr(s)) return -__LINE__;
        pos++;
    }
    ndn_buf_check_close(s);
    if (SyncCheckDecodeErr(s)) return -__LINE__;
    return count;
}

extern struct ndn_charbuf *
SyncNameForIndexbuf(const unsigned char *buf, struct ndn_indexbuf *comps) {
    struct ndn_charbuf *name = ndn_charbuf_create();
    ndn_name_init(name);
    int i = 0;
    int nComp = comps->n-1;
    int res = 0;
    for (i = 0; i < nComp; i++) {
        const unsigned char *cp = NULL;
        size_t sz = 0;
        res |= ndn_name_comp_get(buf, comps, i, &cp, &sz);
        if (res < 0) break;
        res |= ndn_name_append(name, cp, sz);
        if (res < 0) break;
    }
    if (res < 0) {
        SyncNoteErr("SyncNameForIndexbuf failed");
        ndn_charbuf_destroy(&name);
        return NULL;
    }
    return name;
}

extern struct ndn_charbuf *
SyncUriForName(struct ndn_charbuf *name) {
    struct ndn_charbuf *ret = ndn_charbuf_create();
    if (name == NULL)
        ndn_charbuf_append_string(ret, "(null)");
    else ndn_uri_append(ret, name->buf, name->length, 0);
    return ret;
}

extern struct ndn_charbuf *
SyncConstructCommandPrefix(struct SyncRootStruct *root, char *marker) {
    struct ndn_charbuf *prefix = ndn_charbuf_create();
    int res = 0;
    ndn_name_init(prefix);
    if (root->topoPrefix != NULL && root->topoPrefix->length > 0) {
        // the topo (if any) always comes first
        res |= SyncAppendAllComponents(prefix, root->topoPrefix);
    }
    // the command comes after the topo
    ndn_name_append_str(prefix, marker);
    res |= ndn_name_append(prefix, root->sliceHash->buf, root->sliceHash->length);
    
    if (res < 0) {
        ndn_charbuf_destroy(&prefix);
    }
    return prefix;
}


/////////////////////////////////////////////////////////////////
// Routines for dealing with hashes.
/////////////////////////////////////////////////////////////////

extern void
SyncGetHashPtr(const struct ndn_buf_decoder *hd,
               const unsigned char ** xp, ssize_t *xs) {
    struct ndn_buf_decoder xds = *hd;
    struct ndn_buf_decoder *xd = &xds;
    size_t us = 0;
    if (ndn_buf_match_dtag(xd, NDN_DTAG_SyncContentHash)) {
        ndn_buf_advance(xd);
        if (ndn_buf_match_blob(xd, xp, &us)) ndn_buf_advance(xd);
        ndn_buf_check_close(xd);
    } else if (ndn_buf_match_dtag(xd, NDN_DTAG_Component)) {
        ndn_buf_advance(xd);
        if (ndn_buf_match_blob(xd, xp, &us)) ndn_buf_advance(xd);
        ndn_buf_check_close(xd);
    } else if (ndn_buf_match_dtag(xd, NDN_DTAG_Name)) {
        ndn_buf_advance(xd);
        for (;;) {
            if (!ndn_buf_match_dtag(xd, NDN_DTAG_Component)) break;
            ndn_buf_advance(xd);
            if (ndn_buf_match_blob(xd, xp, &us)) ndn_buf_advance(xd);
            ndn_buf_check_close(xd);
        }
        ndn_buf_check_close(xd);
    }
    xs[0] = (ssize_t) us;
    if (SyncCheckDecodeErr(xd)) {
        // close bug
        xp[0] = NULL;
        xs[0] = 0;
        SyncSetDecodeErr(xd, -__LINE__);
    }
}

extern int
SyncCmpHashesRaw(const unsigned char * xp, ssize_t xs,
                 const unsigned char * yp, ssize_t ys) {
    if (xs < ys) return -1;
    if (xs > ys) return 1;
    return memcmp(xp, yp, xs);
}

extern int
SyncCompareHash(struct ndn_charbuf *hashX, struct ndn_charbuf *hashY) {
    if (hashX == hashY) return 0;
    if (hashX == NULL) return -1;
    if (hashY == NULL) return 1;
    size_t lenX = hashX->length;
    size_t lenY = hashY->length;
    if (lenX < lenY) return -1;
    if (lenX > lenY) return 1;
    return memcmp(hashX->buf, hashY->buf, lenX);
}

// accumulates a simple hash code into the hash accumulator
// hash code is raw bytes
extern void
SyncAccumHashRaw(struct SyncLongHashStruct *hp,
                 const unsigned char * xp, size_t xs) {
    unsigned char *ap = hp->bytes;
    int as = MAX_HASH_BYTES;
    int aLim = hp->pos;
    int c = 0;
    if (xs < 2)
        SyncNoteErr("SyncAccumHashRaw, xs < 2");
    // first, accum from x until no more bytes
    while (xs > 0 && as > 0) {
        int val = c;
        xs--;
        as--;
        val = val + ap[as] + xp[xs];
        c = (val >> 8) & 255;
        ap[as] = val & 255;
    }
    // second, propagate the carry (if any)
    while (c > 0 && as > 0) {
        as--;
        c = c + ap[as];
        ap[as] = c & 255;
        c = (c >> 8) & 255;
    }
    // last, update the position (if less than the original)
    if (as < aLim) hp->pos = as;
}

// accumulates a simple hash code referenced by a decoder
// into the hash accumulator for the composite node
// non-destructive of decoder
extern void
SyncAccumHashInner(struct SyncLongHashStruct *hp,
                   const struct ndn_buf_decoder *d) {
    const unsigned char * xp = NULL;
    ssize_t xs = -1;
    SyncGetHashPtr(d, &xp, &xs);
    if (xs >= 0 && xp != NULL)
        SyncAccumHashRaw(hp, xp, xs);
}

// accumulates a simple hash code referenced by a decoder
// into the hash accumulator for the composite node
// non-destructive of decoder
extern void
SyncAccumHash(struct SyncLongHashStruct *hp, const struct ndn_charbuf *cb) {
    struct ndn_buf_decoder ds;
    struct ndn_buf_decoder *d = SyncInitDecoderFromCharbuf(&ds, cb, 0);
    SyncAccumHashInner(hp, d);
}

extern struct ndn_charbuf *
SyncLongHashToBuf(const struct SyncLongHashStruct *hp) {
    struct ndn_charbuf *ret = ndn_charbuf_create();
    int pos = hp->pos;
    ndn_charbuf_append(ret, hp->bytes+pos, MAX_HASH_BYTES-pos);
    return ret;
}

// makes a small, unsigned hash code from a full hash
// useful to speed up hash table lookups
extern uint32_t
SyncSmallHash(const unsigned char * xp, ssize_t xs) {
    uint32_t ret = 0;
    if (xs > 0 && xp != NULL) {
        int i = 0;
        while (i < xs && i < ((int) sizeof(ret))) {
            ret = (ret << 8) + (xp[i] & 255);
            i++;
        }
    }
    return ret;
}

struct SyncHashInfoList *
SyncNoteHash(struct SyncHashInfoList *head, struct SyncHashCacheEntry *ce) {
    struct SyncHashInfoList *each = head;
    struct SyncHashInfoList *lag = NULL;
    while (each != NULL) {
        struct SyncHashInfoList *next = each->next;
        if (each->ce == ce) {
            // found it, so remove it for now
            if (lag == NULL) head = next;
            else lag->next = next;
            break;
        }
        lag = each;
        each = next;
    }
    if (each == NULL) {
        each = NEW_STRUCT(1, SyncHashInfoList);
        each->ce = ce;
    }
    each->lastSeen = SyncCurrentTime();
    each->lastReplied = 0;
    each->next = head;
    return each;
}

extern struct SyncNameAccum *
SyncExclusionsFromHashList(struct SyncRootStruct *root,
                           struct SyncNameAccum *acc,
                           struct SyncHashInfoList *list) {
    int count = 0;
    int limit = 1000;                   // exclusionLimit, in bytes
    int64_t now = SyncCurrentTime();
    int64_t limitMicros = 1000000 * 10; // exclusionTrig
    if (acc == NULL)
        acc = SyncAllocNameAccum(0);
    
    if (root->currentHash->length > 0) {
        // if the current hash is not empty, start there
        struct ndn_charbuf *hash = root->currentHash;
        struct ndn_charbuf *name = ndn_charbuf_create();
        count = count + hash->length + 8;
        ndn_name_init(name);
        ndn_name_append(name, hash->buf, hash->length);
        SyncNameAccumAppend(acc, name, 0);
    }
    
    while (list != NULL) {
        struct SyncHashCacheEntry *ce = list->ce;
        if (ce != NULL && (ce->state & SyncHashState_remote)
            && (ce->state & SyncHashState_covered)
            && SyncDeltaTime(ce->lastUsed, now) < limitMicros) {
            // any remote root known to be covered is excluded
            struct ndn_charbuf *hash = ce->hash;
            count = count + hash->length + 8;
            if (count > limit)
                // exclusion list is getting too long, so ignore earlier roots
                break;
            struct ndn_charbuf *name = ndn_charbuf_create();
            ndn_name_init(name);
            ndn_name_append(name, hash->buf, hash->length);
            SyncNameAccumAppend(acc, name, 0);
        }
        list = list->next;
    }
    if (acc->len == 0) {
        SyncFreeNameAccum(acc);
        return NULL;
    }
    struct SyncNameAccum *lag = acc;
    if (acc->len == 0) {
        // empty list convention is NULL
        acc = NULL;
    } else {
        // exclusion list must be sorted
        acc = SyncSortNames(root, acc);
    }
    SyncFreeNameAccum(lag);
    return acc;
}


/////////////////////////////////////////////////////////////////
// Routines for appending numbers, hashes and names to a charbuf.
/////////////////////////////////////////////////////////////////

extern int
SyncAppendTaggedNumber(struct ndn_charbuf *cb,
                       enum ndn_dtag dtag,
                       unsigned val) {
    int res = ndnb_tagged_putf(cb, dtag, "%u", val);
    return res;
}

// appends a sequence of random bytes
extern int
SyncAppendRandomBytes(struct ndn_charbuf *cb, int n) {
    size_t len = cb->length;
    ndn_charbuf_reserve(cb, n);
    unsigned char *dst = cb->buf + len;
    int i = 0;
    while (i < n) {
        unsigned int r = random();
        dst[i] = (unsigned char) (r & 255);
        i++;
    }
    cb->length = len + n;
    return 0;
}

// appends a random hash code as a ContentHash
extern int
SyncAppendRandomHash(struct ndn_charbuf *cb, int n) {
    int res = ndn_charbuf_append_tt(cb, NDN_DTAG_SyncContentHash, NDN_DTAG);
    res |= ndn_charbuf_append_tt(cb, n, NDN_BLOB);
    res |= SyncAppendRandomBytes(cb, n);
    res |= ndn_charbuf_append_closer(cb);
    return res;
}

// appends a random name of nComp random-length components plus a random hash
extern int
SyncAppendRandomName(struct ndn_charbuf *cb, int nComp, int maxCompLen) {
    struct ndn_charbuf *rb = ndn_charbuf_create();
    int res = ndn_charbuf_append_tt(cb, NDN_DTAG_Name, NDN_DTAG);
    res |= ndn_charbuf_append_closer(cb);
    while (nComp > 0 && res == 0) {
        unsigned nb = random();
        nb = (nb % (maxCompLen+1));
        ndn_charbuf_reset(rb);
        SyncAppendRandomBytes(rb, nb);
        res |= ndn_name_append(cb, rb->buf, nb);
        nComp--;
    }
    // always have a hash code as the last component
    ndn_charbuf_reset(rb);
    res |= SyncAppendRandomBytes(rb, DEFAULT_HASH_BYTES);
    res |= ndn_name_append(cb, rb->buf, rb->length);
    
    ndn_charbuf_destroy(&rb);
    
    return res;
}

// appendElementInner appends the ndnb encoding from the decoder to the cb output
// types supported: NDN_DTAG_Name, NDN_DTAG_SyncContentHash, NDN_DTAG_BinaryValue
// any error returns < 0
// this routine advances the decoder!
extern int
SyncAppendElementInner(struct ndn_charbuf *cb, struct ndn_buf_decoder *d) {
    int res = 0;
    int src = 0;
    if (ndn_buf_match_dtag(d, NDN_DTAG_Name)) {
        ndn_buf_advance(d);
        int res = ndn_charbuf_append_tt(cb, NDN_DTAG_Name, NDN_DTAG);
        res |= ndn_charbuf_append_closer(cb);
        while (ndn_buf_match_dtag(d, NDN_DTAG_Component)) {
            const unsigned char *cPtr = NULL;
            size_t cSize = 0;
            ndn_buf_advance(d);
            if (ndn_buf_match_blob(d, &cPtr, &cSize)) ndn_buf_advance(d);
            res |= ndn_name_append(cb, cPtr, cSize);
            ndn_buf_check_close(d);
        }
        ndn_buf_check_close(d);
    } else if (ndn_buf_match_dtag(d, NDN_DTAG_SyncContentHash)) {
        const unsigned char *cPtr = NULL;
        size_t cSize = 0;
        ndn_buf_advance(d);
        if (ndn_buf_match_blob(d, &cPtr, &cSize)) ndn_buf_advance(d);
        res |= ndnb_append_tagged_blob(cb, NDN_DTAG_SyncContentHash, cPtr, cSize);
    } else if (ndn_buf_match_dtag(d, NDN_DTAG_BinaryValue)) {
        const unsigned char *cPtr = NULL;
        size_t cSize = 0;
        ndn_buf_advance(d);
        if (ndn_buf_match_blob(d, &cPtr, &cSize)) ndn_buf_advance(d);
        res |= ndnb_append_tagged_blob(cb, NDN_DTAG_BinaryValue, cPtr, cSize);
    } else res = -__LINE__;
    if (SyncCheckDecodeErr(d)) src = -__LINE__;
    if (res == 0) res = src;
    return res;
}

// appendElement appends the ndnb encoding from the src to the dst
// types supported: NDN_DTAG_Name, NDN_DTAG_SyncContentHash, NDN_DTAG_BinaryValue
// any error returns < 0
extern int
SyncAppendElement(struct ndn_charbuf *dst, const struct ndn_charbuf *src) {
    struct ndn_buf_decoder ds;
    struct ndn_buf_decoder *d = SyncInitDecoderFromCharbuf(&ds, src, 0);
    int res = SyncAppendElementInner(dst, d);
    return res;
}

extern struct ndn_charbuf *
SyncExtractName(struct ndn_buf_decoder *d) {
    struct ndn_charbuf *name = NULL;
    if (ndn_buf_match_dtag(d, NDN_DTAG_Name)) {
        name = ndn_charbuf_create();
        int res = SyncAppendElementInner(name, d);
        if (res < 0) {
            // parse error, so get rid of the buffer
            ndn_charbuf_destroy(&name);
            SyncSetDecodeErr(d, -__LINE__);
        }
    } else
        SyncSetDecodeErr(d, -__LINE__);
    return name;
}

extern struct ndn_charbuf *
SyncCopyName(const struct ndn_charbuf *name) {
    struct ndn_charbuf *ret = ndn_charbuf_create();
    ndn_charbuf_append_charbuf(ret, name);
    return ret;
}

///////////////////////////////////////////////////////
// Routines for simple parsing
///////////////////////////////////////////////////////

extern unsigned
SyncParseUnsigned(struct ndn_buf_decoder *d, enum ndn_dtag dtag) {
    uintmax_t val = 0;
    if (ndn_buf_match_dtag(d, dtag)) {
        ndn_buf_advance(d);
        if (ndn_parse_uintmax(d, &val) >= 0) {
            ndn_buf_check_close(d);
            if (SyncCheckDecodeErr(d) == 0)
                return val;
        }
    }
    SET_ERR(d);
    return val;
}

extern ssize_t
SyncParseHash(struct ndn_buf_decoder *d) {
    ssize_t off = d->decoder.token_index;
    ndn_parse_required_tagged_BLOB(d, NDN_DTAG_SyncContentHash, 0, MAX_HASH_BYTES);
    return off;
}

extern ssize_t
SyncParseName(struct ndn_buf_decoder *d) {
    ssize_t off = d->decoder.token_index;
    if (ndn_buf_match_dtag(d, NDN_DTAG_Name)) {
        ndn_buf_advance(d);
        while (ndn_buf_match_dtag(d, NDN_DTAG_Component)) {
            ndn_buf_advance(d);
            if (ndn_buf_match_blob(d, NULL, NULL)) ndn_buf_advance(d);
            ndn_buf_check_close(d);
        }
        ndn_buf_check_close(d);
    } else SET_ERR(d);
    return off;
}

////////////////////////////////////////
// Name and Node Accumulators
////////////////////////////////////////

extern struct SyncNameAccum *
SyncAllocNameAccum(int lim) {
    struct SyncNameAccum *na = NEW_STRUCT(1, SyncNameAccum);
    if (lim < 4) lim = 4;
    na->lim = lim;
    na->ents = NEW_STRUCT(lim, SyncNameAccumEntry);
    return na;
}

extern struct SyncNameAccum *
SyncFreeNameAccum(struct SyncNameAccum *na) {
    if (na != NULL) {
        if (na->ents != NULL) free(na->ents);
        free(na);
    }
    return NULL;
}

extern struct SyncNameAccum *
SyncFreeNameAccumAndNames(struct SyncNameAccum *na) {
    if (na != NULL) {
        if (na->ents != NULL) {
            int i = 0;
            for (i = 0; i < na->len; i++) {
                struct ndn_charbuf *name = na->ents[i].name;
                if (name != NULL) {
                    ndn_charbuf_destroy(&name);
                    na->ents[i].name = NULL;
                }
            }
            free(na->ents);
            na->ents = NULL;
        }
        free(na);
    }
    return NULL;
}

extern int
SyncNameAccumSorter(IndexSorter_Base base,
                    IndexSorter_Index x, IndexSorter_Index y) {
    struct SyncNameAccum *na = (struct SyncNameAccum *) base->client;
    IndexSorter_Index len = na->len;
    if (x < len && y < len) {
        struct ndn_charbuf *cbx = na->ents[x].name;
        struct ndn_charbuf *cby = na->ents[y].name;
        int cmp = SyncCmpNames(cbx, cby);
        if (cmp != SYNC_BAD_CMP) return cmp;
    }
    SyncNoteErr("nameAccumSorter");
    return 0;
}

extern int
SyncNameAccumAppend(struct SyncNameAccum *na,
                    struct ndn_charbuf *name,
                    intmax_t data) {
    if (name == NULL || name->length == 0)
        SyncNoteErr("SyncNameAccumAppend");

    struct SyncNameAccumEntry *ents = na->ents;
    int len = na->len;
    if (len == na->lim) {
        // expand the storage
        int newLim = na->lim + na->lim/2 + 4;
        struct SyncNameAccumEntry *newEnts = NEW_STRUCT(newLim, SyncNameAccumEntry);
        memcpy(newEnts, ents, len*sizeof(struct SyncNameAccumEntry));
        free(ents);
        na->lim = newLim;
        ents = newEnts;
        na->ents = newEnts;
    }
    ents[len].name = name;
    ents[len].data = data;
    na->len = len + 1;
    return 1;
}

extern struct ndn_charbuf *
SyncNameAccumCanon(struct SyncNameAccum *na,
                   const struct ndn_charbuf *name) {
    struct ndn_charbuf *found = NULL;
    int i = 0;
    // scan for an existing name
    for (i = 0; i < na->len; i++) {
        int cmp = SyncCmpNames(name, na->ents[i].name);
        if (cmp == 0) {
            // existing name found, bump the count
            found = na->ents[i].name;
            na->ents[i].data++;
            break;
        }
    }
    if (found == NULL) {
        // make a new one and append it
        found = ndn_charbuf_create();
        ndn_charbuf_append_charbuf(found, name);
        SyncNameAccumAppend(na, found, 1);
    }
    return found;
}

extern struct SyncNodeAccum *
SyncAllocNodeAccum(int lim) {
    struct SyncNodeAccum *na = NEW_STRUCT(1, SyncNodeAccum);
    if (lim < 4) lim = 4;
    na->lim = lim;
    na->ents = NEW_ANY(lim, struct SyncNodeComposite *);
    return na;
}

extern struct SyncNodeAccum *
SyncFreeNodeAccum(struct SyncNodeAccum *na) {
    int i;
    if (na != NULL) {
        if (na->ents != NULL) {
            for (i = 0; i < na->len; i++) {
                if (na->ents[i]) {
                    SyncNodeDecRC(na->ents[i]);
                    na->ents[i] = NULL;
                }
            }
            free(na->ents);
        }
        free(na);
    }
    return NULL;
}

extern void
SyncAccumNode(struct SyncNodeAccum *na, struct SyncNodeComposite *nc) {
    struct SyncNodeComposite **ents = na->ents;
    int len = na->len;
    if (len == na->lim) {
        // expand the storage
        int newLim = na->lim + na->lim/2 + 4;
        struct SyncNodeComposite **newEnts = NEW_ANY(newLim,
                                                     struct SyncNodeComposite *);
        memcpy(newEnts, ents, len*sizeof(struct SyncNodeComposite *));
        free(ents);
        na->lim = newLim;
        ents = newEnts;
        na->ents = newEnts;
    }
    ents[len] = nc;
    na->len = len + 1;
    SyncNodeIncRC(nc);
}

extern int
SyncAddName(struct SyncBaseStruct *base,
            struct ndn_charbuf *name,
            uint64_t seq_num) {
    static char *here = "Sync.SyncAddName";
    struct SyncPrivate *priv = base->priv;
    int debug = base->debug;
    struct SyncRootStruct *root = priv->rootHead;
    int count = 0;
    while (root != NULL) {
        if (SyncRootLookupName(root, name) == SyncRootLookupCode_covered) {
            // ANY matching root gets an addition
            // add the name for later processing
            struct SyncRootPrivate *rp = root->priv;
            struct ndn_charbuf *prev = NULL;
            int pos = root->namesToAdd->len;
            if (pos > 0) prev = root->namesToAdd->ents[pos-1].name;
            if (prev != NULL && SyncCmpNames(name, prev) == 0) {
                // this is a duplicate, so forget it!
                if (debug >= NDNL_FINE) {
                    SyncNoteUri(root, here, "ignore dup", name);
                }
            } else {
                // not obviously a duplicate
                uint64_t sn = seq_num;
                if (sn == 0) {
                    // TBD: is there a better inference method?
                    sn = rp->max_seq_num_stable;
                    if (rp->max_seq_num_build > sn)
                        sn = rp->max_seq_num_build;
                }
                SyncNameAccumAppend(root->namesToAdd, SyncCopyName(name), sn);
                count++;
                if (sn > rp->max_seq_num_seen)
                    rp->max_seq_num_seen = sn;
                if (debug >= NDNL_FINE) {
                    SyncNoteUri(root, here, "added", name);
                }
            }
        }
        root = root->next;
    }
    return count;
}

// take a list of names and sort them, removing duplicates!
// should leave src empty  
extern struct SyncNameAccum *
SyncSortNames(struct SyncRootStruct *root, struct SyncNameAccum *src) {
    char *here = "Sync.sortNames";
    if (src == NULL) return NULL;
    IndexSorter_Index ixLim = src->len;
    IndexSorter_Base ixBase = IndexSorter_New(ixLim, -1);
    ixBase->sorter = SyncNameAccumSorter;
    ixBase->client = src;
    IndexSorter_Index ix = 0;
    for (ix = 0; ix < ixLim; ix++) IndexSorter_Add(ixBase, ix);
    struct SyncNameAccum *dst = SyncAllocNameAccum(ixLim);
    struct ndn_charbuf *lag = NULL;
    for (ix = 0; ix < ixLim; ix++) {
        IndexSorter_Index j = IndexSorter_Rem(ixBase);
        if (j >= ixLim) {
            SyncNoteFailed(root, here, "rem failed", __LINE__);
            break;
        }
        struct ndn_charbuf *name = src->ents[j].name;
        src->ents[j].name = NULL;
        if (name == NULL) {
            SyncNoteFailed(root, here, "name == NULL", __LINE__);
            break;
        }
        if (lag == NULL || SyncCmpNames(lag, name) != 0) {
            // only append the name if it is not a duplicate
            SyncNameAccumAppend(dst, name, src->ents[j].data);
            lag = name;
        } else {
            // this name needs to be destroyed
            ndn_charbuf_destroy(&name);
        }
    }    
    src->len = 0;
    IndexSorter_Free(&ixBase);
    return dst;
}


///////////////////////////////////////////////////////
// Routines for simple interest creation
///////////////////////////////////////////////////////

static int
appendLifetime(struct ndn_charbuf *cb, int lifetime) {
    unsigned char buf[sizeof(int32_t)];
    int32_t dreck = lifetime << 12;
    int pos = sizeof(int32_t);
    int res = 0;
    while (dreck > 0 && pos > 0) {
        pos--;
        buf[pos] = dreck & 255;
        dreck = dreck >> 8;
    }
    res |= ndnb_append_tagged_blob(cb, NDN_DTAG_InterestLifetime,
                                   buf+pos, sizeof(buf)-pos);
    return res;
}

static int
appendExclusions(struct ndn_charbuf *cb, struct SyncNameAccum *excl) {
    if (excl != NULL) {
        int i = 0;
        ndn_charbuf_append_tt(cb, NDN_DTAG_Exclude, NDN_DTAG);
        for (i = 0; i < excl->len; i++) {
            struct ndn_charbuf *name = excl->ents[i].name;
            // append just the first component
            struct ndn_buf_decoder ds;
            struct ndn_buf_decoder *d = SyncInitDecoderFromCharbuf(&ds, name, 0);
            size_t cSize = 0;
            if (ndn_buf_match_dtag(d, NDN_DTAG_Name)) {
                ndn_buf_advance(d);
                if (ndn_buf_match_dtag(d, NDN_DTAG_Component)) {
                    ndn_buf_advance(d);
                    const unsigned char *cPtr = NULL;
                    if (ndn_buf_match_blob(d, &cPtr, &cSize)) {
                        ndn_buf_advance(d);
                        ndnb_append_tagged_blob(cb, NDN_DTAG_Component, cPtr, cSize);
                    }
                }
            }
            if (cSize == 0) return -__LINE__;
        }
        ndn_charbuf_append_closer(cb); /* </Exclude> */
        return 1;
    }
    return 0;
}

extern struct ndn_charbuf *
SyncGenInterest(struct ndn_charbuf *name,
                int scope, int lifetime, int maxSuffix, int childPref,
                struct SyncNameAccum *excl) {
    struct ndn_charbuf *cb = ndn_charbuf_create();
    ndn_charbuf_append_tt(cb, NDN_DTAG_Interest, NDN_DTAG);
    int res = 0;
    if (name == NULL) {
        res |= ndn_charbuf_append_tt(cb, NDN_DTAG_Name, NDN_DTAG);
        res |= ndn_charbuf_append_closer(cb); /* </Name> */
    } else {
        ndn_charbuf_append_charbuf(cb, name);
    }
    if (maxSuffix >= 0)
        ndnb_tagged_putf(cb, NDN_DTAG_MaxSuffixComponents, "%d", maxSuffix);
    res |= appendExclusions(cb, excl);
    if (childPref >= 0)
        // low bit determines least/most preference
        ndnb_tagged_putf(cb, NDN_DTAG_ChildSelector, "%d", childPref);
    if (scope >= 0)
        ndnb_tagged_putf(cb, NDN_DTAG_Scope, "%d", scope);
    if (lifetime > 0)
        appendLifetime(cb, lifetime);
    ndn_charbuf_append_closer(cb); /* </Interest> */
    if (res < 0) {
        ndn_charbuf_destroy(&cb);
    }
    return cb;
}

///////////////////////////////////////////////////////
// Routines for local repo read/write
///////////////////////////////////////////////////////

#define UseLocalTopoPrefix 1
extern struct ndn_charbuf *
SyncNameForLocalNode(struct SyncRootStruct *root, struct ndn_charbuf *hash) {
    // form the name of the node
    // use the NodeFetch convention, but at the local host
    struct ndn_charbuf *sh = root->sliceHash;
    struct ndn_charbuf *nm = ndn_charbuf_create();
    int res = 0;
#ifdef UseLocalTopoPrefix
    // new method used root->topoPrefix
    res |= ndn_charbuf_append_charbuf(nm, root->topoPrefix);
#else    
    // old method used localhost instead of topoPrefix
     res |= ndn_name_init(nm);
     res |= ndn_name_append_str(nm, "\xC1.M.S.localhost");
#endif
    res |= ndn_name_append_str(nm, "\xC1.S.nf");
    res |= ndn_name_append(nm, sh->buf, sh->length);
    res |= ndn_name_append(nm, hash->buf, hash->length);
    if (res < 0) ndn_charbuf_destroy(&nm);
    return nm;
}

extern int
SyncPointerToContent(struct ndn_charbuf *cb, struct ndn_parsed_ContentObject *pco,
                     const unsigned char **xp, size_t *xs) {
    struct ndn_parsed_ContentObject pcos;
    int res = 0;
    if (pco == NULL) {
        // not already parsed, so do it now
        pco = &pcos;
        res = ndn_parse_ContentObject(cb->buf, cb->length,
                                      pco, NULL);
    }
    if (res >= 0)
        // worth trying to extract the content
        res = ndn_content_get_value(cb->buf, cb->length, pco, xp, xs);
    return res;
}

extern struct ndn_charbuf *
SyncSignBuf(struct SyncBaseStruct *base,
            struct ndn_charbuf *cb,
            struct ndn_charbuf *name,
            long fresh, int flags) {
    struct ndn_charbuf *cob = ndn_charbuf_create();
    struct ndn_signing_params sp = NDN_SIGNING_PARAMS_INIT;
    
    if (cb != NULL) {
        // signing content, will put as data
        sp.type = NDN_CONTENT_DATA;
    } else {
        // cb == NULL requests deletion
        cb = ndn_charbuf_create();
        sp.type = NDN_CONTENT_GONE;
    }
    sp.sp_flags |= flags;
    
    if (fresh > 0 && fresh <= freshLimit) {
        sp.template_ndnb = ndn_charbuf_create();
        ndn_charbuf_append_tt(sp.template_ndnb, NDN_DTAG_SignedInfo, NDN_DTAG);
        ndnb_tagged_putf(sp.template_ndnb, NDN_DTAG_FreshnessSeconds, "%ld", fresh);
        sp.sp_flags |= NDN_SP_TEMPL_FRESHNESS;
        ndn_charbuf_append_closer(sp.template_ndnb);
    }
    
    int res = ndn_sign_content(base->sd->ndn,
                               cob,
                               name,
                               &sp,
                               cb->buf,
                               cb->length);
    
    if (sp.template_ndnb != NULL) 
        ndn_charbuf_destroy(&sp.template_ndnb);
    if (sp.type == NDN_CONTENT_GONE)
        ndn_charbuf_destroy(&cb);
    if (res < 0) {
        // it did not work, so return the output buffer
        ndn_charbuf_destroy(&cob);
        return NULL;
    }
    return cob;
}

extern int
SyncLocalRepoStore(struct SyncBaseStruct *base,
                   struct ndn_charbuf *name,
                   struct ndn_charbuf *content,
                   int flags) {
    char *here = "Sync.SyncLocalRepoStore";
    int res = -__LINE__;
    struct sync_plumbing *sd = base->sd;
    if (sd->client_methods->r_sync_local_store == NULL)
        return -__LINE__;
    struct ndn_charbuf *cob = SyncSignBuf(base, content, name, -1, flags);
    char *why = NULL;
    if (cob == NULL) {
        why = "signing failed";
        res = -__LINE__;
    } else {
        res = sd->client_methods->r_sync_local_store(sd, cob);
        if (res < 0) {
            why = "store failed";
            res = -__LINE__;
        }
        ndn_charbuf_destroy(&cob);
    }
    if (why != NULL)
        if (base->debug >= NDNL_ERROR)
            SyncNoteUriBase(base, here, why, name);
    return res;
}

extern int
SyncLocalRepoFetch(struct SyncBaseStruct *base,
                   struct ndn_charbuf *name,
                   struct ndn_charbuf *cb,
                   struct ndn_parsed_ContentObject *pco) {
    char *here = "Sync.SyncLocalRepoFetch";
    struct ndn_charbuf *interest = SyncGenInterest(name, 1, 1, -1, 1, NULL);
    struct ndn_parsed_ContentObject pcos;
    if (pco == NULL) pco = &pcos;
    struct sync_plumbing *sd = base->sd;
    if (sd->client_methods->r_sync_lookup == NULL)
        return -__LINE__;
    if (interest == NULL) return -__LINE__;
    int res = sd->client_methods->r_sync_lookup(sd, interest, cb);
    char *why = NULL;
    ndn_charbuf_destroy(&interest);
    if (res < 0) {
        why = "fetch failed";
        res = -__LINE__;
    } else {
        res = ndn_parse_ContentObject(cb->buf, cb->length, pco, NULL);
        if (res < 0) why = "parse failed";
        else {
            res = ndn_verify_content(base->sd->ndn, cb->buf, pco);
            if (res < 0) why = "verify failed";
        }
    }
    if (why != NULL)
        if (base->debug >= NDNL_ERROR)
            SyncNoteUriBase(base, here, why, name);
    return res;
}



