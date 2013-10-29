/**
 * @file ndnr_store.c
 * 
 * Part of ndnr -  NDNx Repository Daemon.
 *
 */

/*
 * Portions Copyright (C) 2013 Regents of the University of California.
 * 
 * Based on the CCNx C Library by PARC.
 * Copyright (C) 2011, 2013 Palo Alto Research Center, Inc.
 *
 * This work is free software; you can redistribute it and/or modify it under
 * the terms of the GNU General Public License version 2 as published by the
 * Free Software Foundation.
 * This work is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License
 * for more details. You should have received a copy of the GNU General Public
 * License along with this program; if not, write to the
 * Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301, USA.
 */
 
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netdb.h>
#include <poll.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <netinet/in.h>

#include <ndn/bloom.h>
#include <ndn/btree_content.h>
#include <ndn/ndn.h>
#include <ndn/ndn_private.h>
#include <ndn/charbuf.h>
#include <ndn/face_mgmt.h>
#include <ndn/hashtb.h>
#include <ndn/indexbuf.h>
#include <ndn/schedule.h>
#include <ndn/reg_mgmt.h>
#include <ndn/uri.h>

#include "ndnr_private.h"

#include "ndnr_stats.h"
#include "ndnr_store.h"
#include "ndnr_init.h"
#include "ndnr_link.h"
#include "ndnr_util.h"
#include "ndnr_proto.h"
#include "ndnr_msg.h"
#include "ndnr_sync.h"
#include "ndnr_match.h"
#include "ndnr_sendq.h"
#include "ndnr_io.h"

struct content_entry {
    ndnr_accession accession;   /**< permanent repository id */
    ndnr_cookie cookie;         /**< for in-memory references */
    int flags;                  /**< see below - use accessor functions */
    int size;                   /**< size of ContentObject */
    struct ndn_charbuf *flatname; /**< for skiplist, et. al. */
    struct ndn_charbuf *cob;    /**< may contain ContentObject, or be NULL */
};

static const unsigned char *bogon = NULL;
const ndnr_accession r_store_mark_repoFile1 = ((ndnr_accession)1) << 48;

static int
r_store_set_flatname(struct ndnr_handle *h, struct content_entry *content,
                     struct ndn_parsed_ContentObject *pco);
static int
r_store_content_btree_insert(struct ndnr_handle *h,
                             struct content_entry *content,
                             struct ndn_parsed_ContentObject *pco,
                             ndnr_accession *accession);

#define FAILIF(cond) do {} while ((cond) && r_store_fatal(h, __func__, __LINE__))
#define CHKSYS(res) FAILIF((res) == -1)
#define CHKRES(res) FAILIF((res) < 0)
#define CHKPTR(p)   FAILIF((p) == NULL)

static int
r_store_fatal(struct ndnr_handle *h, const char *fn, int lineno)
{
    if (h != NULL) {
        ndnr_msg(h,
                 "fatal error in %s, line %d, errno %d%s",
                 fn, lineno, errno, strerror(errno));
    }
    abort();
}

PUBLIC ndnr_accession
r_store_content_accession(struct ndnr_handle *h, struct content_entry *content)
{
    return(content->accession);
}

PUBLIC ndnr_cookie
r_store_content_cookie(struct ndnr_handle *h, struct content_entry *content)
{
    return(content->cookie);
}

PUBLIC size_t
r_store_content_size(struct ndnr_handle *h, struct content_entry *content)
{
    return(content->size);
}

static off_t
r_store_offset_from_accession(struct ndnr_handle *h, ndnr_accession a)
{
    return(a & ((((ndnr_accession)1) << 48) - 1));
}

static unsigned
r_store_repofile_from_accession(struct ndnr_handle *h, ndnr_accession a)
{
    /* Initially this should always be 1 */
    return(a >> 48);
}


static const unsigned char *
r_store_content_mapped(struct ndnr_handle *h, struct content_entry *content)
{
    return(NULL);
}

static const unsigned char *
r_store_content_read(struct ndnr_handle *h, struct content_entry *content)
{
    unsigned repofile;
    off_t offset;
    struct ndn_charbuf *cob = NULL;
    ssize_t rres = 0;
    int fd = -1;
    unsigned char buf[8800];
    struct ndn_skeleton_decoder decoder = {0};
    struct ndn_skeleton_decoder *d = &decoder;
    ssize_t dres;
    
    repofile = r_store_repofile_from_accession(h, content->accession);
    offset = r_store_offset_from_accession(h, content->accession);
    if (repofile != 1)
        goto Bail;
    if (content->cob != NULL)
        goto Bail;
    fd = r_io_repo_data_file_fd(h, repofile, 0);
    if (fd == -1)
        goto Bail;
    cob = ndn_charbuf_create_n(content->size);
    if (cob == NULL)
        goto Bail;
    if (content->size > 0) {
        rres = pread(fd, cob->buf, content->size, offset);
        if (rres == content->size) {
            cob->length = content->size;
            content->cob = cob;
            h->cob_count++;
            return(cob->buf);
        }
        if (rres == -1)
            ndnr_msg(h, "r_store_content_read %u :%s (errno = %d)",
                     fd, strerror(errno), errno);
        else
            ndnr_msg(h, "r_store_content_read %u expected %d bytes, but got %d",
                     fd, (int)content->size, (int)rres);
    } else {
        rres = pread(fd, buf, 8800, offset); // XXX - should be symbolic
        if (rres == -1) {
            ndnr_msg(h, "r_store_content_read %u :%s (errno = %d)",
                     fd, strerror(errno), errno);
            goto Bail;
        }
        dres = ndn_skeleton_decode(d, buf, rres);
        if (d->state != 0) {
            ndnr_msg(h, "r_store_content_read %u : error parsing cob", fd);
            goto Bail;
        }
        content->size = dres;
        if (ndn_charbuf_append(cob, buf, dres) < 0)
            goto Bail;
        content->cob = cob;
        h->cob_count++;
        return(cob->buf);        
    }
Bail:
    ndn_charbuf_destroy(&cob);
    return(NULL);
}

/**
 *  If the content appears to be safely stored in the repository,
 *  removes any buffered copy.
 * @returns 0 if buffer was removed, -1 if not.
 */
PUBLIC int
r_store_content_trim(struct ndnr_handle *h, struct content_entry *content)
{
    if (content->accession != NDNR_NULL_ACCESSION && content->cob != NULL) {
        ndn_charbuf_destroy(&content->cob);
        h->cob_count--;
        return(0);
    }
    return(-1);
}

/**
 *  Evict recoverable content from in-memory buffers
 */
PUBLIC void
r_store_trim(struct ndnr_handle *h, unsigned long limit)
{
    struct content_entry *content = NULL;
    int checklimit;
    unsigned before;
    unsigned rover;
    unsigned mask;
    
    r_store_index_needs_cleaning(h);
    before = h->cob_count;
    if (before <= limit)
        return;
    checklimit = h->cookie_limit;
    mask = h->cookie_limit - 1;
    for (rover = (h->trim_rover & mask);
         checklimit > 0 && h->cob_count > limit;
         checklimit--, rover = (rover + 1) & mask) {
        content = h->content_by_cookie[rover];
        if (content != NULL)
            r_store_content_trim(h, content);
    }
    h->trim_rover = rover;
    if (NDNSHOULDLOG(h, sdf, NDNL_FINER))
        ndnr_msg(h, "trimmed %u cobs", before - h->cob_count);
}

/**
 *  Get the base address of the content object
 *
 * This may involve reading the object in.  Caller should not assume that
 * the address will stay valid after it relinquishes control, either by
 * returning or by calling routines that might invalidate objects.
 *
 */
PUBLIC const unsigned char *
r_store_content_base(struct ndnr_handle *h, struct content_entry *content)
{
    const unsigned char *ans = NULL;
    
    if (content->cob != NULL && content->cob->length == content->size) {
        ans = content->cob->buf;
        goto Finish;
    }
    if (content->accession == NDNR_NULL_ACCESSION)
        goto Finish;
    ans = r_store_content_mapped(h, content);
    if (ans != NULL)
        goto Finish;
    ans = r_store_content_read(h, content);
Finish:
    if (ans != NULL) {
        /* Sanity check - make sure first 2 and last 2 bytes are good */
        if (content->size < 5 || ans[0] != 0x04 || ans[1] != 0x82 ||
            ans[content->size - 1] != 0 || ans[content->size - 2] != 0) {
            bogon = ans; /* for debugger */
            ans = NULL;
        }
    }
    if (ans == NULL || NDNSHOULDLOG(h, xxxx, NDNL_FINEST))
        ndnr_msg(h, "r_store_content_base.%d returning %p (acc=0x%jx, cookie=%u)",
                 __LINE__,
                 ans,
                 ndnr_accession_encode(h, content->accession),
                 (unsigned)content->cookie);
    return(ans);
}

PUBLIC int
r_store_name_append_components(struct ndn_charbuf *dst,
                               struct ndnr_handle *h,
                               struct content_entry *content,
                               int skip,
                               int count)
{
    int res;
    
    res = ndn_name_append_flatname(dst,
                                   content->flatname->buf,
                                   content->flatname->length, skip, count);
    return(res);
}

PUBLIC int
r_store_content_flags(struct content_entry *content)
{
    return(content->flags);
}

PUBLIC int
r_store_content_change_flags(struct content_entry *content, int set, int clear)
{
    int old = content->flags;
    content->flags |= set;
    content->flags &= ~clear;
    return(old);
}

/**
 * Write a file named index/stable that contains the size of
 * repoFile1 when the repository is shut down.
 */
static int
r_store_write_stable_point(struct ndnr_handle *h)
{
    struct ndn_charbuf *path = NULL;
    struct ndn_charbuf *cb = NULL;
    int fd, res;
    
    path = ndn_charbuf_create();
    cb = ndn_charbuf_create();
    if (path == NULL || cb == NULL) {
        ndnr_msg(h, "memory allocation failure writing stable mark");
        goto Bail;
    }
    ndn_charbuf_putf(path, "%s/index/stable", h->directory);
    unlink(ndn_charbuf_as_string(path)); /* Should not exist, but just in case. */
    fd = open(ndn_charbuf_as_string(path),
              O_CREAT | O_EXCL | O_WRONLY | O_TRUNC, 0666);
    if (fd == -1) {
        ndnr_msg(h, "cannot write stable mark %s: %s",
                 ndn_charbuf_as_string(path), strerror(errno));
        unlink(ndn_charbuf_as_string(path));
    }
    else {
        ndn_charbuf_putf(cb, "%ju", (uintmax_t)(h->stable));
        res = write(fd, cb->buf, cb->length);
        close(fd);
        if (res != cb->length) {
            unlink(ndn_charbuf_as_string(path));
            ndnr_msg(h, "cannot write stable mark %s: unexpected write result %d",
                     ndn_charbuf_as_string(path), res);
        }
        if (NDNSHOULDLOG(h, dfsdf, NDNL_INFO))
            ndnr_msg(h, "Index marked stable - %s", ndn_charbuf_as_string(cb));
    }
Bail:
    ndn_charbuf_destroy(&path);
    ndn_charbuf_destroy(&cb);
    return(0);
}

/**
 * Read the former size of repoFile1 from index/stable, and remove
 * the latter.
 */
static void
r_store_read_stable_point(struct ndnr_handle *h)
{
    struct ndn_charbuf *path = NULL;
    struct ndn_charbuf *cb = NULL;
    int fd;
    int i;
    ssize_t rres;
    uintmax_t val;
    unsigned char c;
    
    path = ndn_charbuf_create();
    cb = ndn_charbuf_create();
    ndn_charbuf_putf(path, "%s/index/stable", h->directory);
    fd = open(ndn_charbuf_as_string(path), O_RDONLY, 0666);
    if (fd != -1) {
        rres = read(fd, ndn_charbuf_reserve(cb, 80), 80);
        if (rres > 0)
            cb->length = rres;
        close(fd);
        if (NDNSHOULDLOG(h, dfsdf, NDNL_INFO))
            ndnr_msg(h, "Last stable at %s", ndn_charbuf_as_string(cb));
    }
    for (val = 0, i = 0; i < cb->length; i++) {
        c = cb->buf[i];
        if ('0' <= c && c <= '9')
            val = val * 10 + (c - '0');
        else
            break;
    }
    if (i == 0 || i < cb->length) {
        ndnr_msg(h, "Bad stable mark - %s", ndn_charbuf_as_string(cb));
        h->stable = 0;
    }
    else {
        h->stable = val;
        unlink(ndn_charbuf_as_string(path));
    }
    ndn_charbuf_destroy(&path);
    ndn_charbuf_destroy(&cb);
}

/**
 * Log a bit if we are taking a while to re-index.
 */
static int
r_store_reindexing(struct ndn_schedule *sched,
                   void *clienth,
                   struct ndn_scheduled_event *ev,
                   int flags)
{
    struct ndnr_handle *h = clienth;
    struct fdholder *in = NULL;
    unsigned pct;
    
    if ((flags & NDN_SCHEDULE_CANCEL) != 0)
        return(0);
    in = r_io_fdholder_from_fd(h, h->active_in_fd);
    if (in == NULL)
        return(0);
    pct = ndnr_meter_total(in->meter[FM_BYTI]) / ((h->startupbytes / 100) + 1);
    if (pct >= 100)
        return(0);
    ndnr_msg(h, "indexing %u%% complete", pct);
    return(2000000);
}

/**
 * Select power of 2 between l and m + 1 (if possible).
 */
static unsigned
choose_limit(unsigned l, unsigned m)
{
    unsigned k;
    
    for (k = 0; k < l; k = 2 * k + 1)
        continue;
    while (k > (m | 1) || k + 1 < k)
        k >>= 1;
    return(k + 1);
}

static void
cleanup_content_entry(struct ndnr_handle *h, struct content_entry *content)
{
    unsigned i;
    
    if ((content->flags & NDN_CONTENT_ENTRY_STALE) != 0)
        h->n_stale--;
    if (NDNSHOULDLOG(h, LM_4, NDNL_FINER))
        ndnr_debug_content(h, __LINE__, "remove", NULL, content);
    /* Remove the cookie reference */
    i = content->cookie & (h->cookie_limit - 1);
    if (h->content_by_cookie[i] == content)
        h->content_by_cookie[i] = NULL;
    content->cookie = 0;
    ndn_charbuf_destroy(&content->flatname);
    if (content->cob != NULL) {
        h->cob_count--;
        ndn_charbuf_destroy(&content->cob);
    }
    free(content);    
}
static void
finalize_accession(struct hashtb_enumerator *e)
{
    struct ndnr_handle *h = hashtb_get_param(e->ht, NULL);
    struct content_by_accession_entry *entry = e->data;
    
    cleanup_content_entry(h, entry->content);
}

PUBLIC void
r_store_init(struct ndnr_handle *h)
{
    struct ndn_btree *btree = NULL;
    struct ndn_btree_node *node = NULL;
    struct hashtb_param param = {0};
    int i;
    int j;
    int res;
    struct ndn_charbuf *path = NULL;
    struct ndn_charbuf *msgs = NULL;
    off_t offset;
    
    path = ndn_charbuf_create();
    param.finalize_data = h;
    param.finalize = &finalize_accession;
    
    h->cob_limit = r_init_confval(h, "NDNR_CONTENT_CACHE", 16, 2000000, 4201);
    h->cookie_limit = choose_limit(h->cob_limit, (ndnr_cookie)(~0U));
    h->content_by_cookie = calloc(h->cookie_limit, sizeof(h->content_by_cookie[0]));
    CHKPTR(h->content_by_cookie);
    h->content_by_accession_tab = hashtb_create(sizeof(struct content_by_accession_entry), &param);
    CHKPTR(h->content_by_accession_tab);
    h->btree = btree = ndn_btree_create();
    CHKPTR(btree);
    FAILIF(btree->nextnodeid != 1);
    ndn_charbuf_putf(path, "%s/index", h->directory);
    res = mkdir(ndn_charbuf_as_string(path), 0700);
    if (res != 0 && errno != EEXIST)
        r_init_fail(h, __LINE__, ndn_charbuf_as_string(path), errno);
    else {
        msgs = ndn_charbuf_create();
        btree->io = ndn_btree_io_from_directory(ndn_charbuf_as_string(path), msgs);
        if (btree->io == NULL)
            res = errno;
        if (msgs->length != 0 && NDNSHOULDLOG(h, sffdsdf, NDNL_WARNING)) {
            ndnr_msg(h, "while initializing %s - %s",
                     ndn_charbuf_as_string(path),
                     ndn_charbuf_as_string(msgs));
        }
        ndn_charbuf_destroy(&msgs);
        if (btree->io == NULL)
            r_init_fail(h, __LINE__, ndn_charbuf_as_string(path), res);
    }
    node = ndn_btree_getnode(btree, 1, 0);
    if (btree->io != NULL)
        btree->nextnodeid = btree->io->maxnodeid + 1;
    CHKPTR(node);
    if (node->buf->length == 0) {
        res = ndn_btree_init_node(node, 0, 'R', 0);
        CHKSYS(res);
    }
    ndn_charbuf_destroy(&path);
    if (h->running == -1)
        return;
    r_store_read_stable_point(h);
    h->active_in_fd = -1;
    h->active_out_fd = r_io_open_repo_data_file(h, "repoFile1", 1); /* output */
    offset = lseek(h->active_out_fd, 0, SEEK_END);
    h->startupbytes = offset;
    if (offset != h->stable || node->corrupt != 0) {
        ndnr_msg(h, "Index not current - resetting");
        ndn_btree_init_node(node, 0, 'R', 0);
        node = NULL;
        ndn_btree_destroy(&h->btree);
        path = ndn_charbuf_create();
        /* Remove old index files to avoid confusion */
        for (i = 1, j = 0; i > 0 && j < 3; i++) {
            path->length = 0;
            res = ndn_charbuf_putf(path, "%s/index/%d", h->directory, i);
            if (res >= 0)
                res = unlink(ndn_charbuf_as_string(path));
            if (res < 0)
                j++;
        }
        h->btree = btree = ndn_btree_create();
        path->length = 0;
        ndn_charbuf_putf(path, "%s/index", h->directory);
        btree->io = ndn_btree_io_from_directory(ndn_charbuf_as_string(path), msgs);
        CHKPTR(btree->io);
        btree->io->maxnodeid = 0;
        btree->nextnodeid = 1;
        node = ndn_btree_getnode(btree, 1, 0);
        btree->nextnodeid = btree->io->maxnodeid + 1;
        ndn_btree_init_node(node, 0, 'R', 0);
        h->stable = 0;
        h->active_in_fd = r_io_open_repo_data_file(h, "repoFile1", 0); /* input */
        ndn_charbuf_destroy(&path);
        if (NDNSHOULDLOG(h, dfds, NDNL_INFO))
            ndn_schedule_event(h->sched, 50000, r_store_reindexing, NULL, 0);
    }
    if (NDNSHOULDLOG(h, weuyg, NDNL_FINEST)) {
        FILE *dumpfile = NULL;
        
        path = ndn_charbuf_create();
        ndn_charbuf_putf(path, "%s/index/btree_check.out", h->directory);
        dumpfile = fopen(ndn_charbuf_as_string(path), "w");
        res = ndn_btree_check(btree, dumpfile);
        if (dumpfile != NULL) {
            fclose(dumpfile);
            dumpfile = NULL;
        }
        else
            path->length = 0;
        ndnr_msg(h, "ndn_btree_check returned %d (%s)",
                    res, ndn_charbuf_as_string(path));
        ndn_charbuf_destroy(&path);
        if (res < 0)
            r_init_fail(h, __LINE__, "index is corrupt", res);
    }
    btree->full = r_init_confval(h, "NDNR_BTREE_MAX_FANOUT", 4, 9999, 1999);
    btree->full0 = r_init_confval(h, "NDNR_BTREE_MAX_LEAF_ENTRIES", 4, 9999, 1999);
    btree->nodebytes = r_init_confval(h, "NDNR_BTREE_MAX_NODE_BYTES", 1024, 8388608, 2097152);
    btree->nodepool = r_init_confval(h, "NDNR_BTREE_NODE_POOL", 16, 2000000, 512);
    if (h->running != -1)
        r_store_index_needs_cleaning(h);
}

PUBLIC int
r_store_final(struct ndnr_handle *h, int stable) {
    int res;
    
    res = ndn_btree_destroy(&h->btree);
    if (res < 0)
        ndnr_msg(h, "r_store_final.%d-%d Errors while closing index", __LINE__, res);
    if (res >= 0 && stable)
        res = r_store_write_stable_point(h);
    return(res);
}
    
PUBLIC struct content_entry *
r_store_content_from_accession(struct ndnr_handle *h, ndnr_accession accession)
{
    struct ndn_parsed_ContentObject obj = {0};
    struct content_entry *content = NULL;
    struct content_by_accession_entry *entry;
    const unsigned char *content_base = NULL;
    int res;
    ndnr_accession acc;
    
    if (accession == NDNR_NULL_ACCESSION)
        return(NULL);
    entry = hashtb_lookup(h->content_by_accession_tab,
                          &accession, sizeof(accession));
    if (entry != NULL) {
        h->content_from_accession_hits++;
        return(entry->content);
    }
    h->content_from_accession_misses++;
    content = calloc(1, sizeof(*content));
    CHKPTR(content);
    content->cookie = 0;
    content->accession = accession;
    content->cob = NULL;
    content->size = 0;
    content_base = r_store_content_base(h, content);
    if (content_base == NULL || content->size == 0)
        goto Bail;
    res = r_store_set_flatname(h, content, &obj);
    if (res < 0) goto Bail;
    r_store_enroll_content(h, content);
    res = r_store_content_btree_insert(h, content, &obj, &acc);
    if (res < 0) goto Bail;
    if (res == 1 || NDNSHOULDLOG(h, sdf, NDNL_FINEST))
        ndnr_debug_content(h, __LINE__, "content/accession", NULL, content);
    return(content);
Bail:
    ndnr_msg(h, "r_store_content_from_accession.%d failed 0x%jx",
             __LINE__, ndnr_accession_encode(h, accession));
    r_store_forget_content(h, &content);
    return(content);
}

PUBLIC struct content_entry *
r_store_content_from_cookie(struct ndnr_handle *h, ndnr_cookie cookie)
{
    struct content_entry *ans = NULL;
    
    ans = h->content_by_cookie[cookie & (h->cookie_limit - 1)];
    if (ans != NULL && ans->cookie != cookie)
        ans = NULL;
    return(ans);
}

/**
 * This makes a cookie for content, and, if it has an accession number already,
 * enters it into the content_by_accession_tab.  Does not index by name.
 */
PUBLIC ndnr_cookie
r_store_enroll_content(struct ndnr_handle *h, struct content_entry *content)
{
    ndnr_cookie cookie;
    unsigned mask;
    
    mask = h->cookie_limit - 1;
    cookie = ++(h->cookie);
    if (cookie == 0)
        cookie = ++(h->cookie); /* Cookie numbers may wrap */
    // XXX - check for persistence here, if we add that
    r_store_forget_content(h, &(h->content_by_cookie[cookie & mask]));
    content->cookie = cookie;
    h->content_by_cookie[cookie & mask] = content;
    if (content->accession != NDNR_NULL_ACCESSION) {
        struct hashtb_enumerator ee;
        struct hashtb_enumerator *e = &ee;
        ndnr_accession accession = content->accession;
        struct content_by_accession_entry *entry = NULL;
        hashtb_start(h->content_by_accession_tab, e);
        hashtb_seek(e, &accession, sizeof(accession), 0);
        entry = e->data;
        if (entry != NULL)
            entry->content = content;
        hashtb_end(e);
        content->flags |= NDN_CONTENT_ENTRY_STABLE;
    }
    return(cookie);
}

/** @returns 2 if content was added to index, 1 if it was there but had no accession, 0 if it was already there, -1 for error */
static int
r_store_content_btree_insert(struct ndnr_handle *h,
                             struct content_entry *content,
                             struct ndn_parsed_ContentObject *pco,
                             ndnr_accession *accp)
{
    const unsigned char *content_base = NULL;
    struct ndn_btree *btree = NULL;
    struct ndn_btree_node *leaf = NULL;
    struct ndn_btree_node *node = NULL;
    struct ndn_charbuf *flat = NULL;
    int i;
    int limit;
    int res;

    btree = h->btree;
    if (btree == NULL)
        return(-1);
    flat = content->flatname;
    if (flat == NULL)
        return(-1);
    res = ndn_btree_lookup(h->btree, flat->buf, flat->length, &leaf);
    if (res < 0)
        return(-1);
    i = NDN_BT_SRCH_INDEX(res);
    if (NDN_BT_SRCH_FOUND(res)) {
        *accp = ndnr_accession_decode(h, ndn_btree_content_cobid(leaf, i));
        return(*accp == NDNR_NULL_ACCESSION);
    }
    else {
        content_base = r_store_content_base(h, content);
        if (content_base == NULL)
            return(-1);
        res = ndn_btree_prepare_for_update(h->btree, leaf);
        if (res < 0)
            return(-1);
        res = ndn_btree_insert_content(leaf, i,
                                       ndnr_accession_encode(h, content->accession),
                                       content_base,
                                       pco,
                                       content->flatname);
        if (res < 0)
            return(-1);
        if (ndn_btree_oversize(btree, leaf)) {
            res = ndn_btree_split(btree, leaf);
            for (limit = 100; res >= 0 && btree->nextsplit != 0; limit--) {
                if (limit == 0) abort();
                node = ndn_btree_getnode(btree, btree->nextsplit, 0);
                if (node == NULL)
                    return(-1);
                res = ndn_btree_split(btree, node);
            }
        }
        r_store_index_needs_cleaning(h);
        
        *accp = content->accession;
        return(2);
    }
}

/**
 *  Remove internal representation of a content object
 */
PUBLIC void
r_store_forget_content(struct ndnr_handle *h, struct content_entry **pentry)
{
    struct content_entry *entry = *pentry;
    
    if (entry == NULL)
        return;
    *pentry = NULL;
    /* Remove the accession reference */
    /* more cleanup, including the content_by_cookie cleanup,
     * is done by the finalizer for the accession hash table
     */
    if (entry->accession != NDNR_NULL_ACCESSION) {
        struct hashtb_enumerator ee;
        struct hashtb_enumerator *e = &ee;
        hashtb_start(h->content_by_accession_tab, e);
        if (hashtb_seek(e, &entry->accession, sizeof(entry->accession), 0) ==
            HT_NEW_ENTRY) {
            ndnr_msg(h, "orphaned content %llu",
                     (unsigned long long)(entry->accession));
            hashtb_delete(e);
            hashtb_end(e);
            return;
        }
        entry->accession = NDNR_NULL_ACCESSION;
        hashtb_delete(e);
        hashtb_end(e);
    } else {
        if (NDNSHOULDLOG(h, sdf, NDNL_FINER)) {
              ndnr_debug_content(h, __LINE__, "removing unenrolled content", NULL, entry);
        }
        cleanup_content_entry(h, entry);
    }
}

/**
 *  Get a handle on the content object that matches key, or if there is
 * no match, the one that would come just after it.
 *
 * The key is in flatname format.
 */
static struct content_entry *    
r_store_look(struct ndnr_handle *h, const unsigned char *key, size_t size)
{
    struct content_entry *content = NULL;
    struct ndn_btree_node *leaf = NULL;
    ndnr_accession accession;
    int ndx;
    int res;

    res = ndn_btree_lookup(h->btree, key, size, &leaf);
    if (res >= 0) {
        ndx = NDN_BT_SRCH_INDEX(res);
        if (ndx == ndn_btree_node_nent(leaf)) {
            res = ndn_btree_next_leaf(h->btree, leaf, &leaf);
            if (res <= 0)
                return(NULL);
            ndx = 0;
        }
        accession = ndnr_accession_decode(h, ndn_btree_content_cobid(leaf, ndx));
        if (accession != NDNR_NULL_ACCESSION) {
            struct content_by_accession_entry *entry;
            entry = hashtb_lookup(h->content_by_accession_tab,
                                    &accession, sizeof(accession));
            if (entry != NULL)
                content = entry->content;
            if (content == NULL) {
                /* Construct handle without actually reading the cob */
                res = ndn_btree_content_cobsz(leaf, ndx);
                content = calloc(1, sizeof(*content));
                if (res > 0 && content != NULL) {
                    content->accession = accession;
                    content->cob = NULL;
                    content->size = res;
                    content->flatname = ndn_charbuf_create();
                    CHKPTR(content->flatname);
                    res = ndn_btree_key_fetch(content->flatname, leaf, ndx);
                    CHKRES(res);
                    r_store_enroll_content(h, content);
                }
            }
        }
    }
    return(content);
}

/**
 * Extract the flatname representations of the bounds for the
 * next component after the name prefix of the interest.
 * These are exclusive bounds.  The results are appended to
 * lower and upper (when not NULL).  If there is
 * no lower bound, lower will be unchanged.
 * If there is no upper bound, a sentinel value is appended to upper.
 *
 * @returns on success the number of Components in Exclude.
 *          A negative value indicates an error.
 */
static int
ndn_append_interest_bounds(const unsigned char *interest_msg,
                           const struct ndn_parsed_interest *pi,
                           struct ndn_charbuf *lower,
                           struct ndn_charbuf *upper)
{
    struct ndn_buf_decoder decoder;
    struct ndn_buf_decoder *d = NULL;
    size_t xstart = 0;
    size_t xend = 0;
    int atlower = 0;
    int atupper = 0;
    int res = 0;
    int nexcl = 0;
    
    if (pi->offset[NDN_PI_B_Exclude] < pi->offset[NDN_PI_E_Exclude]) {
        d = ndn_buf_decoder_start(&decoder,
                                  interest_msg + pi->offset[NDN_PI_B_Exclude],
                                  pi->offset[NDN_PI_E_Exclude] -
                                  pi->offset[NDN_PI_B_Exclude]);
        ndn_buf_advance(d);
        if (ndn_buf_match_dtag(d, NDN_DTAG_Any)) {
            ndn_buf_advance(d);
            ndn_buf_check_close(d);
            atlower = 1; /* look for <Exclude><Any/><Component>... case */
        }
        else if (ndn_buf_match_dtag(d, NDN_DTAG_Bloom))
            ndn_buf_advance_past_element(d);
        while (ndn_buf_match_dtag(d, NDN_DTAG_Component)) {
            nexcl++;
            xstart = pi->offset[NDN_PI_B_Exclude] + d->decoder.token_index;
            ndn_buf_advance_past_element(d);
            xend = pi->offset[NDN_PI_B_Exclude] + d->decoder.token_index;
            if (atlower && lower != NULL && d->decoder.state >= 0) {
                res = ndn_flatname_append_from_ndnb(lower,
                        interest_msg + xstart, xend - xstart, 0, 1);
                if (res < 0)
                    d->decoder.state = - __LINE__;
            }
            atlower = 0;
            atupper = 0;
            if (ndn_buf_match_dtag(d, NDN_DTAG_Any)) {
                atupper = 1; /* look for ...</Component><Any/></Exclude> case */
                ndn_buf_advance(d);
                ndn_buf_check_close(d);
            }
            else if (ndn_buf_match_dtag(d, NDN_DTAG_Bloom))
                ndn_buf_advance_past_element(d);
        }
        ndn_buf_check_close(d);
        res = d->decoder.state;
    }
    if (upper != NULL) {
        if (atupper && res >= 0)
            res = ndn_flatname_append_from_ndnb(upper,
                     interest_msg + xstart, xend - xstart, 0, 1);
        else
            ndn_charbuf_append(upper, "\377\377\377", 3);
    }
    return (res < 0 ? res : 0);
}

static struct content_entry *
r_store_lookup_backwards(struct ndnr_handle *h,
                         const unsigned char *interest_msg,
                         const struct ndn_parsed_interest *pi,
                         struct ndn_indexbuf *comps)
{
    struct content_entry *content = NULL;
    struct ndn_btree_node *leaf = NULL;
    struct ndn_charbuf *lower = NULL;
    struct ndn_charbuf *f = NULL;
    size_t size;
    size_t fsz;
    int errline = 0;
    int try = 0;
    int ndx;
    int res;
    int rnc;
    
    size = pi->offset[NDN_PI_E];
    f = ndn_charbuf_create_n(pi->offset[NDN_PI_E_Name]);
    lower = ndn_charbuf_create();
    if (f == NULL || lower == NULL) { errline = __LINE__; goto Done; };
    rnc = ndn_flatname_from_ndnb(f, interest_msg, size);
    fsz = f->length;
    res = ndn_charbuf_append_charbuf(lower, f);
    if (rnc < 0 || res < 0) { errline = __LINE__; goto Done; };
    res = ndn_append_interest_bounds(interest_msg, pi, lower, f);
    if (res < 0) { errline = __LINE__; goto Done; };
    /* Now f is beyond any we care about */
    res = ndn_btree_lookup(h->btree, f->buf, f->length, &leaf);
    if (res < 0) { errline = __LINE__; goto Done; };
    ndx = NDN_BT_SRCH_INDEX(res);
    for (try = 1;; try++) {
        if (ndx == 0) {
            res = ndn_btree_prev_leaf(h->btree, leaf, &leaf);
            if (res != 1) goto Done;
            ndx = ndn_btree_node_nent(leaf);
            if (ndx <= 0) goto Done;
        }
        ndx -= 1;
        res = ndn_btree_compare(lower->buf, lower->length, leaf, ndx);
        if (res > 0 || (res == 0 && lower->length > fsz))
            goto Done;
        f->length = 0;
        res = ndn_btree_key_fetch(f, leaf, ndx);
        if (res < 0) { errline = __LINE__; goto Done; }
        if (f->length > fsz) {
            rnc = ndn_flatname_next_comp(f->buf + fsz, f->length - fsz);
            if (rnc < 0) { errline = __LINE__; goto Done; };
            f->length = fsz + NDNFLATDELIMSZ(rnc) + NDNFLATDATASZ(rnc);
            res = ndn_btree_lookup(h->btree, f->buf, f->length, &leaf);
            if (res < 0) { errline = __LINE__; goto Done; };
            ndx = NDN_BT_SRCH_INDEX(res);
        }
        else if (f->length < fsz) { errline = __LINE__; goto Done; }
        res = ndn_btree_match_interest(leaf, ndx, interest_msg, pi, f);
        if (res == 1) {
            res = ndn_btree_key_fetch(f, leaf, ndx);
            if (res < 0) { errline = __LINE__; goto Done; }
            content = r_store_look(h, f->buf, f->length);
            goto Done;
        }
        else if (res != 0) { errline = __LINE__; goto Done; }
    }
Done:
    if (errline != 0)
        ndnr_debug_ndnb(h, errline, "match_error", NULL, interest_msg, size);
    else {
        if (content != NULL) {
            h->count_rmc_found += 1;
            h->count_rmc_found_iters += try;
        }
        else {
            h->count_rmc_notfound += 1;
            h->count_rmc_notfound_iters += try;
        }
    }
    ndn_charbuf_destroy(&lower);
    ndn_charbuf_destroy(&f);
    return(content);
}

PUBLIC struct content_entry *
r_store_find_first_match_candidate(struct ndnr_handle *h,
                                   const unsigned char *interest_msg,
                                   const struct ndn_parsed_interest *pi)
{
    struct ndn_charbuf *flatname = NULL;
    struct content_entry *content = NULL;
    
    flatname = ndn_charbuf_create_n(pi->offset[NDN_PI_E]);
    ndn_flatname_from_ndnb(flatname, interest_msg, pi->offset[NDN_PI_E]);
    ndn_append_interest_bounds(interest_msg, pi, flatname, NULL);
    content = r_store_look(h, flatname->buf, flatname->length);
    ndn_charbuf_destroy(&flatname);
    return(content);
}

PUBLIC int
r_store_content_matches_interest_prefix(struct ndnr_handle *h,
                                struct content_entry *content,
                                const unsigned char *interest_msg,
                                size_t interest_size)
{
    struct ndn_charbuf *flatname = ndn_charbuf_create_n(interest_size);
    int ans;
    int cmp;

    ndn_flatname_from_ndnb(flatname, interest_msg, interest_size);
    cmp = ndn_flatname_charbuf_compare(flatname, content->flatname);
    ans = (cmp == 0 || cmp == -9999);
    ndn_charbuf_destroy(&flatname);
    return(ans);
}

PUBLIC struct content_entry *
r_store_content_next(struct ndnr_handle *h, struct content_entry *content)
{
    if (content == NULL)
        return(0);
    /* We need to go past the current name, so make sure there is a 0 byte */
    ndn_charbuf_as_string(content->flatname);
    content = r_store_look(h, content->flatname->buf, content->flatname->length + 1);
    return(content);
}

PUBLIC struct content_entry *
r_store_next_child_at_level(struct ndnr_handle *h,
                    struct content_entry *content, int level)
{
    struct content_entry *next = NULL;
    struct ndn_charbuf *name;
    struct ndn_charbuf *flatname = NULL;
    int res;
    
    if (content == NULL)
        return(NULL);
    name = ndn_charbuf_create();
    ndn_name_init(name);
    res = ndn_name_append_flatname(name,
                                   content->flatname->buf,
                                   content->flatname->length, 0, level + 1);
    if (res < level)
        goto Bail;
    if (res == level)
        res = ndn_name_append(name, NULL, 0);
    else if (res == level + 1)
        res = ndn_name_next_sibling(name); // XXX - would be nice to have a flatname version of this
    if (res < 0)
        goto Bail;
    if (NDNSHOULDLOG(h, LM_8, NDNL_FINER))
        ndnr_debug_ndnb(h, __LINE__, "child_successor", NULL,
                        name->buf, name->length);
    flatname = ndn_charbuf_create();
    ndn_flatname_from_ndnb(flatname, name->buf, name->length);
    next = r_store_look(h, flatname->buf, flatname->length);
    if (next == content) {
        // XXX - I think this case should not occur, but just in case, avoid a loop.
        ndnr_debug_content(h, __LINE__, "urp", NULL, next);
        next = NULL;
    }
Bail:
    ndn_charbuf_destroy(&name);
    ndn_charbuf_destroy(&flatname);
    return(next);
}

PUBLIC struct content_entry *
r_store_lookup(struct ndnr_handle *h,
               const unsigned char *msg,
               const struct ndn_parsed_interest *pi,
               struct ndn_indexbuf *comps)
{
    struct content_entry *content = NULL;
    struct ndn_btree_node *leaf = NULL;
    ndnr_cookie last_match = 0;
    ndnr_accession last_match_acc = NDNR_NULL_ACCESSION;
    struct ndn_charbuf *scratch = NULL;
    size_t size = pi->offset[NDN_PI_E];
    int ndx;
    int res;
    int try;
    
    if ((pi->orderpref & 1) == 1) {
        content = r_store_lookup_backwards(h, msg, pi, comps);
        return(content);
    }
    
    content = r_store_find_first_match_candidate(h, msg, pi);
    if (content != NULL && NDNSHOULDLOG(h, LM_8, NDNL_FINER))
        ndnr_debug_content(h, __LINE__, "first_candidate", NULL,
                           content);
    if (content != NULL &&
        !r_store_content_matches_interest_prefix(h, content, msg, size)) {
            if (NDNSHOULDLOG(h, LM_8, NDNL_FINER))
                ndnr_debug_ndnb(h, __LINE__, "prefix_mismatch", NULL,
                                msg, size);
            content = NULL;
        }
    scratch = ndn_charbuf_create();
    for (try = 1; content != NULL; try++) {
        res = ndn_btree_lookup(h->btree,
                               content->flatname->buf,
                               content->flatname->length,
                               &leaf);
        if (NDN_BT_SRCH_FOUND(res) == 0) {
            ndnr_debug_content(h, __LINE__, "impossible", NULL, content);
            content = NULL;
            break;
        }
        ndx = NDN_BT_SRCH_INDEX(res);
        res = ndn_btree_match_interest(leaf, ndx, msg, pi, scratch);
        if (res == -1) {
            ndnr_debug_ndnb(h, __LINE__, "match_error", NULL, msg, size);
            content = NULL;
            break;
        }
        if (res == 1) {
            if ((pi->orderpref & 1) == 0) // XXX - should be symbolic
                break;
            last_match = content->cookie;
            last_match_acc = content->accession;
            content = r_store_next_child_at_level(h, content, comps->n - 1);
        }
        else
            content = r_store_content_next(h, content);
        if (content != NULL &&
            !r_store_content_matches_interest_prefix(h, content, msg, size))
                content = NULL;
    }
    if (last_match != 0) {
        content = r_store_content_from_cookie(h, last_match);
        if (content == NULL)
            content = r_store_content_from_accession(h, last_match_acc);
    }
    ndn_charbuf_destroy(&scratch);
    if (content != NULL) {
        h->count_lmc_found += 1;
        h->count_lmc_found_iters += try;
    }
    else {
        h->count_lmc_notfound += 1;
        h->count_lmc_notfound_iters += try;
    }
    return(content);
}

/**
 * Find the first content handle that matches the prefix given by the namish,
 * which may be a Name, Interest, ContentObject, ...
 *
 * Does not check the other parts of namish, in particular, does not generate
 * the digest component of a ContentObject.
 */
PUBLIC struct content_entry *
r_store_lookup_ndnb(struct ndnr_handle *h,
                    const unsigned char *namish, size_t size)
{
    struct content_entry *content = NULL;
    struct ndn_charbuf *flatname = NULL;
    int res;
    
    flatname = ndn_charbuf_create();
    if (flatname == NULL)
        goto Bail;
    res = ndn_flatname_from_ndnb(flatname, namish, size);
    if (res < 0)
        goto Bail;
    content = r_store_look(h, flatname->buf, flatname->length);
    if (content != NULL) {
        res = ndn_flatname_charbuf_compare(flatname, content->flatname);
        if (res == 0 || res == -9999) {
            /* prefix matches */
        }
        else
            content = NULL;
    }
Bail:
    ndn_charbuf_destroy(&flatname);
    return(content);
}

/**
 * Mark content as stale
 */
PUBLIC void
r_store_mark_stale(struct ndnr_handle *h, struct content_entry *content)
{
    ndnr_cookie cookie = content->cookie;
    if ((content->flags & NDN_CONTENT_ENTRY_STALE) != 0)
        return;
    if (NDNSHOULDLOG(h, LM_4, NDNL_FINE))
            ndnr_debug_content(h, __LINE__, "stale", NULL, content);
    content->flags |= NDN_CONTENT_ENTRY_STALE;
    h->n_stale++;
    if (cookie < h->min_stale)
        h->min_stale = cookie;
    if (cookie > h->max_stale)
        h->max_stale = cookie;
}

/**
 * Scheduled event that makes content stale when its FreshnessSeconds
 * has expired.
 */
static int
expire_content(struct ndn_schedule *sched,
               void *clienth,
               struct ndn_scheduled_event *ev,
               int flags)
{
    struct ndnr_handle *h = clienth;
    ndnr_cookie cookie = ev->evint;
    struct content_entry *content = NULL;
    if ((flags & NDN_SCHEDULE_CANCEL) != 0)
        return(0);
    content = r_store_content_from_cookie(h, cookie);
    if (content != NULL)
        r_store_mark_stale(h, content);
    return(0);
}

/**
 * Schedules content expiration based on its FreshnessSeconds.
 *
 */
PUBLIC void
r_store_set_content_timer(struct ndnr_handle *h, struct content_entry *content,
                  struct ndn_parsed_ContentObject *pco)
{
    int seconds = 0;
    int microseconds = 0;
    size_t start = pco->offset[NDN_PCO_B_FreshnessSeconds];
    size_t stop  = pco->offset[NDN_PCO_E_FreshnessSeconds];
    const unsigned char *content_msg = NULL;
    if (start == stop)
        return;
    content_msg = r_store_content_base(h, content);
    if (content_msg == NULL) {
        ndnr_debug_content(h, __LINE__, "Missing_content_base", NULL,
                           content);
        return;        
    }
    seconds = ndn_fetch_tagged_nonNegativeInteger(
                NDN_DTAG_FreshnessSeconds,
                content_msg,
                start, stop);
    if (seconds <= 0)
        return;
    if (seconds > ((1U<<31) / 1000000)) {
        ndnr_debug_content(h, __LINE__, "FreshnessSeconds_too_large", NULL,
                           content);
        return;
    }
    microseconds = seconds * 1000000;
    ndn_schedule_event(h->sched, microseconds,
                       &expire_content, NULL, content->cookie);
}

/**
 * Parses content object and sets content->flatname
 */
static int
r_store_set_flatname(struct ndnr_handle *h, struct content_entry *content,
                     struct ndn_parsed_ContentObject *pco)
{
    int res;
    struct ndn_charbuf *flatname = NULL;
    const unsigned char *msg = NULL;
    size_t size;
    
    msg = r_store_content_base(h, content);
    size = content->size;
    if (msg == NULL)
        goto Bail;
    flatname = ndn_charbuf_create();
    if (flatname == NULL)
        goto Bail;    
    res = ndn_parse_ContentObject(msg, size, pco, NULL);
    if (res < 0) {
        ndnr_msg(h, "error parsing ContentObject - code %d", res);
        goto Bail;
    }
    ndn_digest_ContentObject(msg, pco);
    if (pco->digest_bytes != 32)
        goto Bail;
    res = ndn_flatname_from_ndnb(flatname, msg, size);
    if (res < 0) goto Bail;
    res = ndn_flatname_append_component(flatname, pco->digest, pco->digest_bytes);
    if (res < 0) goto Bail;
    content->flatname = flatname;
    flatname = NULL;
    return(0);
Bail:
    ndn_charbuf_destroy(&flatname);
    return(-1);
}

/**
 *  Get the flatname associated with content
 *
 * @returns flatname in a charbuf, which should be treated as read-only.
 */
PUBLIC struct ndn_charbuf *
r_store_content_flatname(struct ndnr_handle *h, struct content_entry *content)
{
    return(content->flatname);
}

PUBLIC struct content_entry *
process_incoming_content(struct ndnr_handle *h, struct fdholder *fdholder,
                         unsigned char *msg, size_t size, off_t *offsetp)
{
    struct ndn_parsed_ContentObject obj = {0};
    int res;
    struct content_entry *content = NULL;
    ndnr_accession accession = NDNR_NULL_ACCESSION;
    
    content = calloc(1, sizeof(*content));
    if (content == NULL)
        goto Bail;    
    content->cob = ndn_charbuf_create();
    if (content->cob == NULL)
        goto Bail;    
    res = ndn_charbuf_append(content->cob, msg, size);
    if (res < 0) goto Bail;
    content->size = size;
    res = r_store_set_flatname(h, content, &obj);
    if (res < 0) goto Bail;
    ndnr_meter_bump(h, fdholder->meter[FM_DATI], 1);
    content->accession = NDNR_NULL_ACCESSION;
    if (fdholder->filedesc == h->active_in_fd && offsetp != NULL) {
        // if we are reading from repoFile1 to rebuild the index we already know
        // the accession number
        content->accession = ((ndnr_accession)*offsetp) | r_store_mark_repoFile1;
    }
    r_store_enroll_content(h, content);
    if (NDNSHOULDLOG(h, LM_4, NDNL_FINE))
        ndnr_debug_content(h, __LINE__, "content_from", fdholder, content);
    res = r_store_content_btree_insert(h, content, &obj, &accession);
    if (res < 0) goto Bail;
    if (res == 0) {
        /* Content was there, with an accession */
        if (NDNSHOULDLOG(h, LM_4, NDNL_FINER))
            ndnr_debug_content(h, __LINE__, "content_duplicate",
                               fdholder, content);
        h->content_dups_recvd++;
        r_store_forget_content(h, &content);
        content = r_store_content_from_accession(h, accession);
        if (content == NULL)
            goto Bail;
    }
    r_store_set_content_timer(h, content, &obj);
    r_match_match_interests(h, content, &obj, NULL, fdholder);
    return(content);
Bail:
    r_store_forget_content(h, &content);
    return(content);
}

PUBLIC int
r_store_content_field_access(struct ndnr_handle *h,
                             struct content_entry *content,
                             enum ndn_dtag dtag,
                             const unsigned char **bufp, size_t *sizep)
{
    int res = -1;
    const unsigned char *content_msg;
    struct ndn_parsed_ContentObject pco = {0};
    
    content_msg = r_store_content_base(h, content);
    if (content_msg == NULL)
        return(-1);
    res = ndn_parse_ContentObject(content_msg, content->size, &pco, NULL);
    if (res < 0)
        return(-1);
    if (dtag == NDN_DTAG_Content)
        res = ndn_ref_tagged_BLOB(NDN_DTAG_Content, content_msg,
                                  pco.offset[NDN_PCO_B_Content],
                                  pco.offset[NDN_PCO_E_Content],
                                  bufp, sizep);
    return(res);
}


PUBLIC int
r_store_set_accession_from_offset(struct ndnr_handle *h,
                                  struct content_entry *content,
                                  struct fdholder *fdholder, off_t offset)
{
    struct ndn_btree_node *leaf = NULL;
    uint_least64_t cobid;
    int ndx;
    int res = -1;
    
    if (offset != (off_t)-1 && content->accession == NDNR_NULL_ACCESSION) {
        struct hashtb_enumerator ee;
        struct hashtb_enumerator *e = &ee;
        struct content_by_accession_entry *entry = NULL;
        
        content->flags |= NDN_CONTENT_ENTRY_STABLE;
        content->accession = ((ndnr_accession)offset) | r_store_mark_repoFile1;
        hashtb_start(h->content_by_accession_tab, e);
        hashtb_seek(e, &content->accession, sizeof(content->accession), 0);
        entry = e->data;
        if (entry != NULL) {
            entry->content = content;
            if (content->cob != NULL)
                h->cob_count++;
        }
        hashtb_end(e);
        if (content->flatname != NULL) {
            res = ndn_btree_lookup(h->btree,
                                   content->flatname->buf,
                                   content->flatname->length, &leaf);
            if (res >= 0 && NDN_BT_SRCH_FOUND(res)) {
                ndx = NDN_BT_SRCH_INDEX(res);
                cobid = ndnr_accession_encode(h, content->accession);
                ndn_btree_prepare_for_update(h->btree, leaf);
                res = ndn_btree_content_set_cobid(leaf, ndx, cobid);
            }
            else
                res = -1;
        }
        if (res >= 0 && content->accession >= h->notify_after) 
            r_sync_notify_content(h, 0, content);
    }
    return(res);
}

PUBLIC void
r_store_send_content(struct ndnr_handle *h, struct fdholder *fdholder, struct content_entry *content)
{
    const unsigned char *content_msg = NULL;
    off_t offset;

    content_msg = r_store_content_base(h, content);
    if (content_msg == NULL) {
        ndnr_debug_content(h, __LINE__, "content_missing", fdholder, content);
        return;        
    }
    if (NDNSHOULDLOG(h, LM_4, NDNL_FINE))
        ndnr_debug_content(h, __LINE__, "content_to", fdholder, content);
    r_link_stuff_and_send(h, fdholder, content_msg, content->size, NULL, 0, &offset);
    if (offset != (off_t)-1 && content->accession == NDNR_NULL_ACCESSION) {
        int res;
        res = r_store_set_accession_from_offset(h, content, fdholder, offset);
        if (res == 0)
            if (NDNSHOULDLOG(h, LM_4, NDNL_FINE))
                ndnr_debug_content(h, __LINE__, "content_stored",
                                   r_io_fdholder_from_fd(h, h->active_out_fd),
                                   content);
    }
}

PUBLIC int
r_store_commit_content(struct ndnr_handle *h, struct content_entry *content)
{
    struct fdholder *fdholder = r_io_fdholder_from_fd(h, h->active_out_fd);
    // XXX - here we need to check if this is something we *should* be storing, according to our policy
    if ((r_store_content_flags(content) & NDN_CONTENT_ENTRY_STABLE) == 0) {
        if (fdholder == NULL)
        {
            ndnr_msg(h, "Repository shutting down due to error storing content.");
            h->running = 0;
            return(-1);
        }
        r_store_send_content(h, r_io_fdholder_from_fd(h, h->active_out_fd), content);
        r_store_content_change_flags(content, NDN_CONTENT_ENTRY_STABLE, 0);
    }
    return(0);
}

PUBLIC void
ndnr_debug_content(struct ndnr_handle *h,
                   int lineno,
                   const char *msg,
                   struct fdholder *fdholder,
                   struct content_entry *content)
{
    struct ndn_charbuf *c = ndn_charbuf_create();
    struct ndn_charbuf *flat = content->flatname;
    
    if (c == NULL)
        return;
    ndn_charbuf_putf(c, "debug.%d %s ", lineno, msg);
    if (fdholder != NULL)
        ndn_charbuf_putf(c, "%u ", fdholder->filedesc);
    if (flat != NULL)
        ndn_uri_append_flatname(c, flat->buf, flat->length, 1);
    ndn_charbuf_putf(c, " (%d bytes)", content->size);
    ndnr_msg(h, "%s", ndn_charbuf_as_string(c));
    ndn_charbuf_destroy(&c);
}

/** Number of btree index writes to do in a batch */
#define NDN_BT_CLEAN_BATCH 3
/** Approximate delay between batches of btree index writes */
#define NDN_BT_CLEAN_TICK_MICROS 65536
static int
r_store_index_cleaner(struct ndn_schedule *sched,
    void *clienth,
    struct ndn_scheduled_event *ev,
    int flags)
{
    struct ndnr_handle *h = clienth;
    struct hashtb_enumerator ee;
    struct hashtb_enumerator *e = &ee;
    struct ndn_btree_node *node = NULL;
    int k;
    int res;
    int overquota;
    
    (void)(sched);
    (void)(ev);
    if ((flags & NDN_SCHEDULE_CANCEL) != 0 ||
         h->btree == NULL || h->btree->io == NULL) {
        h->index_cleaner = NULL;
        ndn_indexbuf_destroy(&h->toclean);
        return(0);
    }
    /* First, work on cleaning the things we already know need cleaning */
    if (h->toclean != NULL) {
        for (k = 0; k < NDN_BT_CLEAN_BATCH && h->toclean->n > 0; k++) {
            node = ndn_btree_rnode(h->btree, h->toclean->buf[--h->toclean->n]);
            if (node != NULL && node->iodata != NULL) {
                res = ndn_btree_chknode(node); /* paranoia */
                if (res < 0 || NDNSHOULDLOG(h, sdfsdffd, NDNL_FINER))
                    ndnr_msg(h, "write index node %u (err %d)",
                             (unsigned)node->nodeid, node->corrupt);
                if (res >= 0) {
                    if (node->clean != node->buf->length)
                        res = h->btree->io->btwrite(h->btree->io, node);
                    if (res < 0)
                        ndnr_msg(h, "failed to write index node %u",
                                 (unsigned)node->nodeid);
                    else
                        node->clean = node->buf->length;
                }
                if (res >= 0 && node->iodata != NULL && node->activity == 0) {
                    if (NDNSHOULDLOG(h, sdfsdffd, NDNL_FINER))
                        ndnr_msg(h, "close index node %u",
                                 (unsigned)node->nodeid);
                    res = ndn_btree_close_node(h->btree, node);
                }
            }
        }
        if (h->toclean->n > 0)
            return(nrand48(h->seed) % (2U * NDN_BT_CLEAN_TICK_MICROS) + 500);
    }
    /* Sweep though and find the nodes that still need cleaning */
    overquota = 0;
    if (h->btree->nodepool >= 16)
        overquota = hashtb_n(h->btree->resident) - h->btree->nodepool;
    hashtb_start(h->btree->resident, e);
    for (node = e->data; node != NULL; node = e->data) {
        if (overquota > 0 &&
              node->activity == 0 &&
              node->iodata == NULL &&
              node->clean == node->buf->length) {
            overquota -= 1;
            if (NDNSHOULDLOG(h, sdfsdffd, NDNL_FINEST))
                ndnr_msg(h, "prune index node %u",
                         (unsigned)node->nodeid);
            hashtb_delete(e);
            continue;
        }
        node->activity /= 2; /* Age the node's activity */
        if (node->clean != node->buf->length ||
            (node->iodata != NULL && node->activity == 0)) {
            if (h->toclean == NULL) {
                h->toclean = ndn_indexbuf_create();
                if (h->toclean == NULL)
                    break;
            }
            ndn_indexbuf_append_element(h->toclean, node->nodeid);
        }
        hashtb_next(e);
    }
    hashtb_end(e);
    /* If nothing to do, shut down cleaner */
    if ((h->toclean == NULL || h->toclean->n == 0) && overquota <= 0 &&
        h->btree->io->openfds <= NDN_BT_OPEN_NODES_IDLE) {
        h->btree->cleanreq = 0;
        h->index_cleaner = NULL;
        ndn_indexbuf_destroy(&h->toclean);
        if (NDNSHOULDLOG(h, sdfsdffd, NDNL_FINE))
            ndnr_msg(h, "index btree nodes all clean");
        
        return(0);
    }
    return(nrand48(h->seed) % (2U * NDN_BT_CLEAN_TICK_MICROS) + 500);
}

PUBLIC void
r_store_index_needs_cleaning(struct ndnr_handle *h)
{
    int k;
    if (h->btree != NULL && h->btree->io != NULL && h->btree->cleanreq > 0) {
        if (h->index_cleaner == NULL) {
            h->index_cleaner = ndn_schedule_event(h->sched,
                                                  NDN_BT_CLEAN_TICK_MICROS,
                                                  r_store_index_cleaner, NULL, 0);
            if (NDNSHOULDLOG(h, sdfsdffd, NDNL_FINER))
                ndnr_msg(h, "index cleaner started");
        }
        /* If necessary, clean in a hurry. */
        for (k = 30; /* Backstop to make sure we do not loop here */
             k > 0 && h->index_cleaner != NULL &&
             h->btree->io->openfds > NDN_BT_OPEN_NODES_LIMIT - 2; k--)
            r_store_index_cleaner(h->sched, h, h->index_cleaner, 0);
        if (k == 0)
            ndnr_msg(h, "index cleaner is in trouble");
    }
}

#undef FAILIF
#undef CHKSYS
#undef CHKRES
#undef CHKPTR
