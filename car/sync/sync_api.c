/**
 * @file sync/sync_api.c
 *
 * Sync library interface.
 * Implements a library interface to the Sync protocol facilities implemented
 * by the Repository
 *
 * Part of the NDNx C Library.
 *
 * Portions Copyright (C) 2013 Regents of the University of California.
 * 
 * Based on the CCNx C Library by PARC.
 * Copyright (C) 2012-2013 Palo Alto Research Center, Inc.
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

#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <sys/time.h>
#include <ndn/ndn.h>
#include <ndn/coding.h>
#include <ndn/digest.h>
#include <ndn/loglevels.h>
#include <ndn/schedule.h>
#include <ndn/sync.h>
#include <ndn/uri.h>
#include <ndn/ndn_private.h>


#include "sync_diff.h"
#include "SyncUtil.h"
#include "SyncNode.h"
#include "SyncPrivate.h"

#define CACHE_PURGE_TRIGGER 60     // cache entry purge, in seconds
#define CACHE_CLEAN_BATCH 16       // seconds between cleaning batches
#define CACHE_CLEAN_DELTA 8        // cache clean batch size
#define ADVISE_NEED_RESET 1        // reset value for adviseNeed
#define UPDATE_STALL_DELTA 15      // seconds used to determine stalled update
#define UPDATE_NEED_DELTA 6        // seconds for adaptive update
#define SHORT_DELAY_MICROS 500    // short delay for quick reschedule
#define COMPARE_ASSUME_BAD 20      // secs since last fetch OK to assume compare failed
#define NODE_SPLIT_TRIGGER 400    // in bytes, triggers node split
#define EXCLUSION_LIMIT 1000       // in bytes, limits exclusion list size
#define EXCLUSION_TRIG 5           // trigger for including root hashes in excl list (secs)
#define STABLE_TIME_TRIG 10        // trigger for storing stable point (secs)
#define HASH_SPLIT_TRIGGER 17      // trigger for splitting based on hash (n/255)
#define NAMES_YIELD_INC 100        // number of names to inc between yield tests
#define NAMES_YIELD_MICROS 20*1000 // number of micros to use as yield trigger

struct ndns_slice {
    unsigned version;
    unsigned nclauses;
    struct ndn_charbuf *topo;
    struct ndn_charbuf *prefix;
    struct ndn_charbuf **clauses; // contents defined in documentation, need utils
};

#define NDNS_FLAGS_SC 1      // start at current root hash.

struct ndns_handle {
    struct sync_plumbing *sync_plumbing;
    struct SyncBaseStruct *base;
    struct SyncRootStruct *root;
    struct ndn_scheduled_event *ev;
    struct ndns_name_closure *nc;
    struct SyncHashCacheEntry *last_ce;
    struct SyncHashCacheEntry *next_ce;
    struct SyncNameAccum *namesToAdd;
    struct SyncHashInfoList *hashSeen;
    struct ndn_closure *registered; // registered action for RA interests
    int debug;
    struct ndn *ndn;
    struct sync_diff_fetch_data *fetch_data;
    struct sync_diff_data *diff_data;
    struct sync_update_data *update_data;
    int needUpdate;
    int64_t add_accum;
    int64_t startTime;
};

/*
 * Utility routines to allocate/deallocate ndns_slice structures
 */
struct ndns_slice *
ndns_slice_create() {
    struct ndns_slice *s = calloc(1, sizeof(*s));
    if (s == NULL)
        return(NULL);
    s->version = SLICE_VERSION;
    s->topo = ndn_charbuf_create_n(8); // name encoding requires minimum 2
    s->prefix = ndn_charbuf_create_n(8);
    if (s->topo == NULL || s->prefix == NULL) {
        ndn_charbuf_destroy(&s->topo);
        ndn_charbuf_destroy(&s->prefix);
        free(s);
        s = NULL;
    } else {
        ndn_name_init(s->topo);
        ndn_name_init(s->prefix);
    }
    return(s);
}
void
ndns_slice_destroy(struct ndns_slice **sp) {
    struct ndns_slice *s = *sp;
    if (s != NULL) {
        ndn_charbuf_destroy(&(s->topo));
        ndn_charbuf_destroy(&(s->prefix));
        if (s->clauses != NULL) {
            while(s->nclauses > 0) {
                s->nclauses--;
                ndn_charbuf_destroy(&(s->clauses[s->nclauses]));
            }
            free(s->clauses);
        }
        free(s);
        *sp = NULL;
    }
}

/*
 * Utility routine to add a clause to a ndns_slice structure
 */
int
ndns_slice_add_clause(struct ndns_slice *s, struct ndn_charbuf *c) {
    struct ndn_charbuf **clauses = NULL;
    struct ndn_charbuf *clause;
    clause = ndn_charbuf_create_n(c->length);
    if (clause == NULL)
        return(-1);
    if (s->clauses == NULL) {
        s->clauses = calloc(1, sizeof(s->clauses[0]));
        if (s->clauses == NULL)
            goto Cleanup;
    } else {
        clauses = realloc(s->clauses, (s->nclauses + 1) * sizeof(s->clauses[0]));
        if (clauses == NULL)
            goto Cleanup;
        s->clauses = clauses;
    }
    ndn_charbuf_append_charbuf(clause, c);
    s->clauses[s->nclauses++] = clause;
    return (0);

Cleanup:
    ndn_charbuf_destroy(&clause);
    return (-1);
}

/*
 * Utility routine to set the topo and prefix fields to copies of the
 * passed in charbufs
 */
int
ndns_slice_set_topo_prefix(struct ndns_slice *s,
                           struct ndn_charbuf *t,
                           struct ndn_charbuf *p) {
    int res = 0;
    if (t != NULL) {
        ndn_charbuf_reset(s->topo);
        res |= ndn_charbuf_append_charbuf(s->topo, t);
    }
    if (p != NULL) {
        ndn_charbuf_reset(s->prefix);
        res |= ndn_charbuf_append_charbuf(s->prefix, p);
    }
    return(res);
}

/*
 * utility, may need to be exported, to append the encoding of a
 * slice to a charbuf
 */
static int
append_slice(struct ndn_charbuf *c, struct ndns_slice *s) {
    int res = 0;
    int i;

    res |= ndnb_element_begin(c, NDN_DTAG_SyncConfigSlice);
    res |= ndnb_tagged_putf(c, NDN_DTAG_SyncVersion, "%u", SLICE_VERSION);
    res |= ndn_charbuf_append_charbuf(c, s->topo);
    res |= ndn_charbuf_append_charbuf(c, s->prefix);
    res |= ndnb_element_begin(c, NDN_DTAG_SyncConfigSliceList);
    for (i = 0; i < s->nclauses ; i++) {
        res |= ndnb_tagged_putf(c, NDN_DTAG_SyncConfigSliceOp, "%u", 0);
        res |= ndn_charbuf_append_charbuf(c, s->clauses[i]);
    }
    res |= ndnb_element_end(c);
    res |= ndnb_element_end(c);
    return (res);
}
/*
 * utility, may need to be exported, to parse the buffer into a given slice
 * structure.
 */
static int
slice_parse(struct ndns_slice *s, const unsigned char *p, size_t size) {
    int res = 0;
    struct ndn_buf_decoder decoder;
    struct ndn_buf_decoder *d = ndn_buf_decoder_start(&decoder, p, size);
    uintmax_t version;
    int op;
    int start;
    struct ndn_charbuf *clause = NULL;

    if (!ndn_buf_match_dtag(d, NDN_DTAG_SyncConfigSlice))
        return (-1);
    ndn_buf_advance(d);
    if (!ndn_buf_match_dtag(d, NDN_DTAG_SyncVersion))
        return (-1);
    ndn_buf_advance(d);
    ndn_parse_uintmax(d, &version);
    ndn_buf_check_close(d);
    if (version != SLICE_VERSION)
        return (-1);
    start = d->decoder.token_index;
    if (ndn_parse_Name(d, NULL) < 0)
        return(-1);
    ndn_charbuf_reset(s->topo);
    res = ndn_charbuf_append(s->topo, p + start, d->decoder.token_index - start);
    if (res < 0)
        return(-1);
    start = d->decoder.token_index;
    if (ndn_parse_Name(d, NULL) < 0)
        return(-1);
    ndn_charbuf_reset(s->prefix);
    res = ndn_charbuf_append(s->prefix, p + start, d->decoder.token_index - start);
    if (res < 0)
        return(-1);
    if (!ndn_buf_match_dtag(d, NDN_DTAG_SyncConfigSliceList))
        return(-1);
    ndn_buf_advance(d);
    clause = ndn_charbuf_create();
    if (clause == NULL)
        return(-1);
    while (ndn_buf_match_dtag(d, NDN_DTAG_SyncConfigSliceOp)) {
        ndn_buf_advance(d);
        op = ndn_parse_nonNegativeInteger(d); // op is a small integer
        ndn_buf_check_close(d);
        if (op != 0)
            break;
        ndn_charbuf_reset(clause);
        start = d->decoder.token_index;
        if (ndn_parse_Name(d, NULL) < 0)
            break;
        res = ndn_charbuf_append(clause, p + start, d->decoder.token_index - start);
        ndns_slice_add_clause(s, clause);
    }
    ndn_charbuf_destroy(&clause);
    ndn_buf_check_close(d); /* </SyncConfigSliceList> */
    ndn_buf_check_close(d); /* </SyncConfigSlice> */
    if (d->decoder.index != size || !NDN_FINAL_DSTATE(d->decoder.state))
        return(-1);
    return(0);
}
/**
 * Construct the name of a Sync configuration slice based on the parameters.
 * @param nm is the ndn_charbuf which will be set to the ndnb encoded Name
 * @param s is the definition of the slice for which the name is required.
 * @returns a ndn_charbuf with the ndnb encoded Name of the slice.
 */

int
ndns_slice_name(struct ndn_charbuf *nm, struct ndns_slice *s)
{
    struct ndn_charbuf *c;
    struct ndn_digest *digest = NULL;
    struct ndn_charbuf *hash = NULL;
    int res = 0;

    c = ndn_charbuf_create();
    if (c == NULL)
        return (-1);
    res = append_slice(c, s);
    if (res < 0)
        goto Cleanup;

    digest = ndn_digest_create(NDN_DIGEST_SHA256);
    hash = ndn_charbuf_create_n(ndn_digest_size(digest));
    if (hash == NULL)
        goto Cleanup;
    ndn_digest_init(digest);
    res |= ndn_digest_update(digest, c->buf, c->length);
    res |= ndn_digest_final(digest, hash->buf, hash->limit);
    if (res < 0)
        goto Cleanup;
    hash->length = hash->limit;
    if (ndn_name_from_uri(nm, "ndn:/%C1.M.S.localhost/%C1.S.cs") < 0)
        res = -1;
    res |= ndn_name_append(nm, hash->buf, hash->length);

Cleanup:
    ndn_charbuf_destroy(&c);
    ndn_digest_destroy(&digest);
    ndn_charbuf_destroy(&hash);
    return (res);
}

/**
 * Read a slice (from a repository) given the name.
 * @param h is the ndn_handle on which to read.
 * @param name is the charbuf containing the name of the sync slice to be read.
 * @param slice is a pointer to a ndns_slice object which will be filled in
 *  on successful return.
 * @returns 0 on success, -1 otherwise.
 */
int
ndns_read_slice(struct ndn *h, struct ndn_charbuf *name,
                struct ndns_slice *slice) {
    struct ndn_parsed_ContentObject pco_space = { 0 };
    struct ndn_parsed_ContentObject *pco = &pco_space;
    struct ndn_charbuf *nc = ndn_charbuf_create_n(name->length);
    struct ndn_charbuf *cob = ndn_charbuf_create();
    const unsigned char *content;
    size_t content_length;
    int res = -1;

    if (nc == NULL || cob == NULL)
        goto Cleanup;

    ndn_charbuf_append_charbuf(nc, name);
    res = ndn_resolve_version(h, nc,  NDN_V_HIGHEST, 100); // XXX: timeout
    if (res < 0)
        goto Cleanup;
    if (res == 0) {
        // TODO: check if the last component is a segment number, chop it off, try again.
    }
    res = ndn_get(h, nc, NULL, 100, cob, pco, NULL, 0);
    if (res < 0)
        goto Cleanup;
    if (pco->type != NDN_CONTENT_DATA) {
        res = -1;
        goto Cleanup;
    }
    res = ndn_content_get_value(cob->buf, cob->length, pco,
                                &content, &content_length);
    if (res < 0)
        goto Cleanup;
    res = slice_parse(slice, content, content_length);

Cleanup:
    ndn_charbuf_destroy(&nc);
    ndn_charbuf_destroy(&cob);
    return (res);
}

struct ndn_charbuf *
make_scope1_template(void) {
    struct ndn_charbuf *templ = NULL;
    templ = ndn_charbuf_create_n(16);
    ndnb_element_begin(templ, NDN_DTAG_Interest);
    ndnb_element_begin(templ, NDN_DTAG_Name);
    ndnb_element_end(templ); /* </Name> */
    ndnb_tagged_putf(templ, NDN_DTAG_Scope, "%u", 1);
    ndnb_element_end(templ); /* </Interest> */
    return(templ);
}

static enum ndn_upcall_res
write_interest_handler (struct ndn_closure *selfp,
                        enum ndn_upcall_kind kind,
                        struct ndn_upcall_info *info) {
    struct ndn_charbuf *cob = selfp->data;
    struct ndn *h = info->h;

    if (kind != NDN_UPCALL_INTEREST)
        return(NDN_UPCALL_RESULT_OK);
    if (ndn_content_matches_interest(cob->buf, cob->length, 1, NULL,
                                     info->interest_ndnb,
                                     info->pi->offset[NDN_PI_E],
                                     info->pi)) {
        ndn_put(info->h, cob->buf, cob->length);
        selfp->intdata = 1;
        ndn_set_run_timeout(h, 0);
        return(NDN_UPCALL_RESULT_INTEREST_CONSUMED);
    }
    return(NDN_UPCALL_RESULT_OK);
}

static int
write_slice(struct ndn *h,
            struct ndns_slice *slice,
            struct ndn_charbuf *name) {
    struct ndn_charbuf *content = NULL;
    unsigned char *cbuf = NULL;
    size_t clength = 0;
    struct ndn_charbuf *sw = NULL;
    struct ndn_charbuf *templ = NULL;
    struct ndn_charbuf *cob = NULL;
    struct ndn_signing_params sparm = NDN_SIGNING_PARAMS_INIT;
    struct ndn_closure *wc = NULL;
    int res;

    sw = ndn_charbuf_create_n(32 + name->length);
    if (sw == NULL) {
        res = -1;
        goto Cleanup;
    }
    ndn_charbuf_append_charbuf(sw, name);
    ndn_name_chop(sw, NULL, -1); // remove segment number
    ndn_name_from_uri(sw, "%C1.R.sw");
    ndn_name_append_nonce(sw);

    // create and sign the content object
    cob = ndn_charbuf_create();
    if (cob == NULL) {
        res = -1;
        goto Cleanup;
    }
    if (slice != NULL) {
        content = ndn_charbuf_create();
        if (content == NULL) {
            res = -1;
            goto Cleanup;
        }
        res = append_slice(content, slice);
        if (res < 0)
            goto Cleanup;
        cbuf = content->buf;
        clength = content->length;
    } else {
        sparm.type = NDN_CONTENT_GONE;
    }

    sparm.sp_flags = NDN_SP_FINAL_BLOCK;
    res = ndn_sign_content(h, cob, name, &sparm, cbuf, clength);
    if (res < 0)
        goto Cleanup;
    // establish handler for interest in the slice content object
    wc = calloc(1, sizeof(*wc));
    if (wc == NULL) {
        res = -1;
        goto Cleanup;
    }
    wc->p = &write_interest_handler;
    wc->data = cob;
    res = ndn_set_interest_filter(h, name, wc);
    if (res < 0)
        goto Cleanup;
    templ = make_scope1_template();
    if (templ == NULL) {
        res = -1;
        goto Cleanup;
    }
    res = ndn_get(h, sw, templ, 1000, NULL, NULL, NULL, 0);
    if (res < 0)
        goto Cleanup;
    ndn_run(h, 1000); // give the repository a chance to fetch the data
    if (wc->intdata != 1) {
        res = -1;
        goto Cleanup;
    }
    res = 0;
Cleanup:
    ndn_set_interest_filter(h, name, NULL);
    if (wc != NULL)
        free(wc);
    ndn_charbuf_destroy(&cob);
    ndn_charbuf_destroy(&content);
    ndn_charbuf_destroy(&sw);
    ndn_charbuf_destroy(&templ);
    return (res);
}

/**
 * Write a ndns_slice object to a repository.
 * @param h is the ndn_handle on which to write.
 * @param slice is a pointer to a ndns_slice object to be written.
 * @param name if non-NULL, is a pointer to a charbuf which will be filled
 *  in with the name of the slice that was written.
 * @returns 0 on success, -1 otherwise.
 */
int
ndns_write_slice(struct ndn *h,
                 struct ndns_slice *slice,
                 struct ndn_charbuf *name) {
    struct ndn_charbuf *n = NULL;
    int res;
    // calculate versioned and segmented name for the slice
    n = ndn_charbuf_create();
    if (n == NULL)
        return(-1);
    res = ndns_slice_name(n, slice);
    if (res < 0)
        goto Cleanup;
    res |= ndn_create_version(h, n, NDN_V_NOW, 0, 0);
    if (name != NULL) {
        ndn_charbuf_reset(name);
        res |= ndn_charbuf_append_charbuf(name, n);
    }
    res |= ndn_name_append_numeric(n, NDN_MARKER_SEQNUM, 0);
    if (res < 0)
        goto Cleanup;
    res = write_slice(h, slice, n);

Cleanup:
    ndn_charbuf_destroy(&n);
    return (res);
}
/**
 * Delete a ndns_slice object from a repository.
 * @param h is the ndn_handle on which to write.
 * @param name is a pointer to a charbuf naming the slice to be deleted.
 * @returns 0 on success, -1 otherwise.
 */
int
ndns_delete_slice(struct ndn *h, struct ndn_charbuf *name) {
    struct ndn_charbuf *n = NULL;
    int res = 0;

    // calculate versioned and segmented name for the slice
    n = ndn_charbuf_create_n(32 + name->length);
    if (n == NULL)
        return(-1);
    res |= ndn_charbuf_append_charbuf(n, name);
    res |= ndn_create_version(h, n, NDN_V_NOW | NDN_V_REPLACE, 0, 0);
    res |= ndn_name_append_numeric(n, NDN_MARKER_SEQNUM, 0);
    if (res >= 0)
        res = write_slice(h, NULL, n);
    ndn_charbuf_destroy(&n);
    return (res);
}

/*
 * local time source for event schedule
 */
static void
gettime(const struct ndn_gettime *self, struct ndn_timeval *result) {
    struct timeval now = {0};
    gettimeofday(&now, 0);
    result->s = now.tv_sec;
    result->micros = now.tv_usec;
}

// types

enum local_flags {
    LF_NULL,
    LF_ADVISE,
    LF_NODE,
    LF_OTHER
};

struct hash_list {
    struct hash_list *next;
    struct SyncHashCacheEntry *ce;
    int64_t lastSeen;
};

// forward declarations

static int
start_interest(struct sync_diff_data *diff_data);


// utilities and stuff

// noteErr2 is used to deliver error messages when there is no
// active root or base

static int
noteErr2(const char *why, const char *msg) {
    fprintf(stderr, "** ERROR: %s, %s\n", why, msg);
    fflush(stderr);
    return -1;
}

static void
my_r_sync_msg(struct sync_plumbing *sd, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stdout, fmt, ap);
    va_end(ap);
    fprintf(stdout, "\n");
    fflush(stdout);
}

// extractNode parses and creates a sync tree node from an upcall info
// returns NULL if there was any kind of error
static struct SyncNodeComposite *
extractNode(struct SyncRootStruct *root, struct ndn_upcall_info *info) {
    // first, find the content
    char *here = "sync_track.extractNode";
    const unsigned char *cp = NULL;
    size_t cs = 0;
    size_t ndnb_size = info->pco->offset[NDN_PCO_E];
    const unsigned char *ndnb = info->content_ndnb;
    int res = ndn_content_get_value(ndnb, ndnb_size, info->pco,
                                    &cp, &cs);
    if (res < 0 || cs < DEFAULT_HASH_BYTES) {
        SyncNoteFailed(root, here, "ndn_content_get_value", __LINE__);
        return NULL;
    }
    
    // second, parse the object
    struct SyncNodeComposite *nc = SyncAllocComposite(root->base);
    struct ndn_buf_decoder ds;
    struct ndn_buf_decoder *d = ndn_buf_decoder_start(&ds, cp, cs);
    res |= SyncParseComposite(nc, d);
    if (res < 0) {
        // failed, so back out of the allocations
        SyncNoteFailed(root, here, "bad parse", -res);
        SyncFreeComposite(nc);
        nc = NULL;
    }
    return nc;
}

/* UNUSED */ struct sync_diff_fetch_data *
check_fetch_data(struct ndns_handle *ch, struct sync_diff_fetch_data *fd) {
    struct sync_diff_fetch_data *each = ch->fetch_data;
    while (each != NULL) {
        struct sync_diff_fetch_data *next = each->next;
        if (each == fd) return fd;
        each = next;
    }
    return NULL;
}

static struct sync_diff_fetch_data *
find_fetch_data(struct ndns_handle *ch, struct SyncHashCacheEntry *ce) {
    struct sync_diff_fetch_data *each = ch->fetch_data;
    while (each != NULL) {
        struct sync_diff_fetch_data *next = each->next;
        if (each->hash_cache_entry == ce) return each;
        each = next;
    }
    return NULL;
}

static int
delink_fetch_data(struct ndns_handle *ch, struct sync_diff_fetch_data *fd) {
    if (fd != NULL) {
        struct sync_diff_fetch_data *each = ch->fetch_data;
        struct sync_diff_fetch_data *lag = NULL;
        while (each != NULL) {
            struct sync_diff_fetch_data *next = each->next;
            if (each == fd) {
                if (lag == NULL) ch->fetch_data = next;
                else lag->next = next;
                return 1;
            }
            lag = each;
            each = next;
        }
    }
    return 0;
}

static void
free_fetch_data(struct ndns_handle *ch, struct sync_diff_fetch_data *fd) {
    if (delink_fetch_data(ch, fd)) {
        struct ndn_closure *action = fd->action;
        if (action != NULL && action->data == fd)
            // break the link here
            action->data = NULL;
        fd->action = NULL;
        // only free the data if it is ours
        free(fd);
    }
}

static void
setCurrentHash(struct SyncRootStruct *root, struct SyncHashCacheEntry *ce) {
    struct ndn_charbuf *hash = root->currentHash;
    hash->length = 0;
    if (ce != NULL)
        ndn_charbuf_append_charbuf(hash, ce->hash);
}

static struct SyncHashCacheEntry *
chooseNextHash(struct ndns_handle *ch) {
    struct SyncHashCacheEntry *nce = ch->next_ce;
    if (nce != NULL && (nce->state & SyncHashState_covered) == 0
        && find_fetch_data(ch, nce) == NULL)
        return nce;
    struct SyncHashInfoList *each = ch->hashSeen;
    while (each != NULL) {
        struct SyncHashCacheEntry *ce = each->ce;
        if (ce != NULL && (ce->state & SyncHashState_covered) == 0
            && (nce == NULL || SyncCompareHash(ce->hash, nce->hash) > 0)
            && find_fetch_data(ch, ce) == NULL)
            return ce;
        each = each->next;
    }
    return NULL;
}

// each_round starts a new comparison or update round,
// provided that the attached sync_diff is not busy
// we reuse the sync_diff_data, but reset the comparison hashes
// if we can't start one, we wait and try again
static int
each_round(struct ndn_schedule *sched,
           void *clienth,
           struct ndn_scheduled_event *ev,
           int flags) {
    if (ev == NULL)
        // not valid
        return -1;
    struct ndns_handle *ch = ev->evdata;
    if (flags & NDN_SCHEDULE_CANCEL || ch == NULL) {
        return -1;
    }
    if (ch->needUpdate) {
        // do an update
        switch (ch->update_data->state) {
            case sync_update_state_init:
            case sync_update_state_error:
            case sync_update_state_done: {
                if (ch->namesToAdd != NULL && ch->namesToAdd->len > 0) {
                    sync_update_start(ch->update_data, ch->namesToAdd);
                } else {
                    // update not very useful
                    ch->needUpdate = 0;
                    return 1000;
                }
            }
            default:
                // we are busy right now
                break;
        }
    } else {
        // do a comparison
        struct sync_diff_data *diff_data = ch->diff_data;
        switch (diff_data->state) {
            case sync_diff_state_init:
            case sync_diff_state_error:
            case sync_diff_state_done: {
                // there is no comparison active
                struct SyncHashCacheEntry *ce = ch->next_ce;
                if (ce != NULL
                    && ((ce->state & SyncHashState_covered) != 0))
                    ce = chooseNextHash(ch);
                if (ce != NULL
                    && ((ce->state & SyncHashState_covered) == 0)
                    && ce != ch->last_ce) {
                    // worth trying
                    ch->next_ce = ce;
                    if (ch->last_ce != NULL)
                        diff_data->hashX = ch->last_ce->hash;
                    if (ch->next_ce != NULL)
                        diff_data->hashY = ch->next_ce->hash;
                    sync_diff_start(diff_data);
                }
            }
            default:
                // we are busy right now
                break;
        }
    }
    return 500000; // 0.5 seconds
}

// start_round schedules a new comparison round,
// cancelling any previously scheduled round
static void
start_round(struct ndns_handle *ch, int micros) {
    struct ndn_scheduled_event *ev = ch->ev;
    if (ev != NULL && ev->action != NULL && ev->evdata == ch)
        // get rid of the existing event
        ndn_schedule_cancel(ch->sync_plumbing->sched, ev);
    // start a new event
    ch->ev = ndn_schedule_event(ch->sync_plumbing->sched,
                                micros,
                                each_round,
                                ch,
                                0);
    return;
}

// my_response is used to handle a reply
static enum ndn_upcall_res
my_response(struct ndn_closure *selfp,
            enum ndn_upcall_kind kind,
            struct ndn_upcall_info *info) {
    static char *here = "sync_track.my_response";
    enum ndn_upcall_res ret = NDN_UPCALL_RESULT_ERR;
    switch (kind) {
        case NDN_UPCALL_FINAL:
            free(selfp);
            ret = NDN_UPCALL_RESULT_OK;
            break;
        case NDN_UPCALL_CONTENT_UNVERIFIED:
            ret = NDN_UPCALL_RESULT_VERIFY;
            break;
        case NDN_UPCALL_CONTENT_KEYMISSING:
            ret = NDN_UPCALL_RESULT_FETCHKEY;
            break;
        case NDN_UPCALL_INTEREST_TIMED_OUT: {
            struct sync_diff_fetch_data *fd = selfp->data;
            //enum local_flags flags = selfp->intdata;
            if (fd == NULL) break;
            struct sync_diff_data *diff_data = fd->diff_data;
            if (diff_data == NULL) break;
            struct ndns_handle *ch = diff_data->client_data;
            free_fetch_data(ch, fd);
            start_round(ch, 10);
            ret = NDN_UPCALL_RESULT_OK;
            break;
        }
        case NDN_UPCALL_CONTENT_RAW:
        case NDN_UPCALL_CONTENT: {
            struct sync_diff_fetch_data *fd = selfp->data;
            enum local_flags flags = selfp->intdata;
            if (fd == NULL) break;
            struct sync_diff_data *diff_data = fd->diff_data;
            if (diff_data == NULL) break;
            struct SyncRootStruct *root = diff_data->root;
            if (root == NULL) break;
            struct ndns_handle *ch = diff_data->client_data;
            struct SyncNodeComposite *nc = extractNode(root, info);
            if (ch->debug >= NDNL_FINE) {
                char fs[1024];
                int pos = 0;
                switch (flags) {
                    case LF_NULL: 
                        pos += snprintf(fs+pos, sizeof(fs)-pos, "null");
                        break;
                    case LF_ADVISE:
                        pos += snprintf(fs+pos, sizeof(fs)-pos, "advise");
                        break;
                    case LF_NODE:
                        pos += snprintf(fs+pos, sizeof(fs)-pos, "node");
                        break;
                    default: 
                        pos += snprintf(fs+pos, sizeof(fs)-pos, "??%d", flags);
                        break;
                }
                if (nc != NULL)
                    pos += snprintf(fs+pos, sizeof(fs)-pos, ", nc OK");
                struct ndn_charbuf *nm = SyncNameForIndexbuf(info->content_ndnb,
                                                             info->content_comps);
                struct ndn_charbuf *uri = SyncUriForName(nm);
                pos += snprintf(fs+pos, sizeof(fs)-pos, ", %s", ndn_charbuf_as_string(uri));
                SyncNoteSimple(diff_data->root, here, fs);
                ndn_charbuf_destroy(&nm);
                ndn_charbuf_destroy(&uri);
            }
            if (nc != NULL) {
                // the node exists, so store it
                // TBD: check the hash?
                struct ndns_handle *ch = diff_data->client_data;
                struct SyncHashCacheEntry *ce = SyncHashEnter(root->ch,
                                                              nc->hash->buf, nc->hash->length,
                                                              SyncHashState_remote);
                if (flags == LF_ADVISE) {
                    ch->hashSeen = SyncNoteHash(ch->hashSeen, ce);
                    if (ch->next_ce == NULL)
                        // have to have an initial place to start
                        ch->next_ce = ce;
                }
                if (ce->ncR == NULL) {
                    // store the node
                    ce->ncR = nc;
                    SyncNodeIncRC(nc);
                } else {
                    // flush the node
                    SyncNodeDecRC(nc);
                    nc = NULL;
                }
                if (flags != LF_NULL) {
                    // from start_interest
                    start_round(ch, 10);
                } else {
                    // from sync_diff
                    sync_diff_note_node(diff_data, ce);
                }
                ret = NDN_UPCALL_RESULT_OK;
            }
            free_fetch_data(ch, fd);
            break;
        default:
            // SHOULD NOT HAPPEN
            break;
        }
    }
    return ret;
}

static enum ndn_upcall_res
advise_interest_arrived(struct ndn_closure *selfp,
                        enum ndn_upcall_kind kind,
                        struct ndn_upcall_info *info) {
    // the reason to have a listener is to be able to listen for changes
    // in the collection without relying on the replies to our root advise
    // interests, which may not receive timely replies (althoug they eventually
    // get replies)
    static char *here = "sync_track.advise_interest_arrived";
    enum ndn_upcall_res ret = NDN_UPCALL_RESULT_ERR;
    switch (kind) {
        case NDN_UPCALL_FINAL:
            free(selfp);
            ret = NDN_UPCALL_RESULT_OK;
            break;
        case NDN_UPCALL_INTEREST: {
            struct ndns_handle *ch = selfp->data;
            if (ch == NULL) {
                // this got cancelled
                ret = NDN_UPCALL_RESULT_OK;
                break;
            }
            struct sync_diff_data *diff_data = ch->diff_data;
            struct SyncRootStruct *root = ch->root;
            //struct SyncBaseStruct *base = root->base;
            int skipToHash = SyncComponentCount(diff_data->root->topoPrefix) + 2;
            // skipToHash gets to the new hash
            // topo + marker + sliceHash
            const unsigned char *hp = NULL;
            size_t hs = 0;
            if (ch->debug >= NDNL_FINE) {
                struct ndn_charbuf *name = SyncNameForIndexbuf(info->interest_ndnb,
                                                               info->interest_comps);
                SyncNoteUri(root, here, "entered", name);
                ndn_charbuf_destroy(&name);
            }
            int cres = ndn_name_comp_get(info->interest_ndnb, info->interest_comps, skipToHash, &hp, &hs);
            if (cres < 0) {
                if (ch->debug >= NDNL_INFO)
                    SyncNoteSimple(diff_data->root, here, "wrong number of interest name components");
                break;
            }
            struct SyncHashCacheEntry *ce = SyncHashEnter(root->ch, hp, hs,
                                                          SyncHashState_remote);
            if (ce == NULL || ce->state & SyncHashState_covered) {
                // should not be added
                if (ch->debug >= NDNL_FINE)
                    SyncNoteSimple(diff_data->root, here, "skipped");
            } else {
                // remember the remote hash, maybe start something
                if (ch->debug >= NDNL_FINE)
                    SyncNoteSimple(diff_data->root, here, "noting");
                ch->hashSeen = SyncNoteHash(ch->hashSeen, ce);
                start_interest(diff_data);
            }
            ret = NDN_UPCALL_RESULT_OK;
            break;
        }
        default:
            // SHOULD NOT HAPPEN
            break;
    }
    return ret;
}

static int
start_interest(struct sync_diff_data *diff_data) {
    static char *here = "sync_track.start_interest";
    struct SyncRootStruct *root = diff_data->root;
    struct SyncBaseStruct *base = root->base;
    struct ndns_handle *ch = diff_data->client_data;
    struct SyncHashCacheEntry *ce = ch->next_ce;
    struct ndn_charbuf *prefix = SyncCopyName(diff_data->root->topoPrefix);
    int res = 0;
    struct ndn *ndn = base->sd->ndn;
    if (ndn == NULL) {
        ndn_charbuf_destroy(&prefix);
        return SyncNoteFailed(root, here, "bad ndn handle", __LINE__);
    }
    res |= ndn_name_append_str(prefix, "\xC1.S.ra");
    res |= ndn_name_append(prefix, root->sliceHash->buf, root->sliceHash->length);
    if (ce != NULL) {
        // append the best component seen
        res |= ndn_name_append(prefix, ce->hash->buf, ce->hash->length);
    } else {
        // append an empty component
        res |= ndn_name_append(prefix, "", 0);
    }
    struct SyncNameAccum *excl = SyncExclusionsFromHashList(root, NULL, ch->hashSeen);
    struct ndn_charbuf *template = SyncGenInterest(NULL,
                                                   base->priv->syncScope,
                                                   base->priv->fetchLifetime,
                                                   -1, -1, excl);
    SyncFreeNameAccumAndNames(excl);
    struct ndn_closure *action = calloc(1, sizeof(*action));
    struct sync_diff_fetch_data *fetch_data = calloc(1, sizeof(*fetch_data));
    fetch_data->diff_data = diff_data;
    fetch_data->action = action;
    fetch_data->startTime = SyncCurrentTime();
    // note: no ce available yet
    action->data = fetch_data;
    action->intdata = LF_ADVISE;
    action->p = &my_response;
    fetch_data->next = ch->fetch_data;
    ch->fetch_data = fetch_data;
    res |= ndn_express_interest(ndn, prefix, action, template);
    ndn_charbuf_destroy(&template);
    if (ch->debug >= NDNL_FINE) {
        SyncNoteUri(diff_data->root, here, "start_interest", prefix);
    }
    ndn_charbuf_destroy(&prefix);
    if (res < 0) {
        SyncNoteFailed(root, here, "ndn_express_interest failed", __LINE__);
        // return the resources, must free fd first!
        free_fetch_data(ch, fetch_data);
        free(action);
        return -1;
    }
    return 1;
}

static int
my_get(struct sync_diff_get_closure *gc,
       struct sync_diff_fetch_data *fd) {
    char *here = "sync_track.my_get";
    struct sync_diff_data *diff_data = gc->diff_data;
    struct ndns_handle *ch = diff_data->client_data;
    struct SyncRootStruct *root = diff_data->root;
    struct SyncBaseStruct *base = root->base;
    struct SyncHashCacheEntry *ce = fd->hash_cache_entry;
    int res = 0;
    struct ndn *ndn = base->sd->ndn;
    if (ndn == NULL)
        return SyncNoteFailed(root, here, "bad ndn handle", __LINE__);
    if (ce == NULL)
        return SyncNoteFailed(root, here, "bad cache entry", __LINE__);
    // first, check for existing fetch of same hash
    struct ndn_charbuf *hash = ce->hash;
    struct ndn_charbuf *name = SyncCopyName(diff_data->root->topoPrefix);
    ndn_name_append_str(name, "\xC1.S.nf");
    res |= ndn_name_append(name, root->sliceHash->buf, root->sliceHash->length);
    if (hash == NULL || hash->length == 0)
        res |= ndn_name_append(name, "", 0);
    else
        res |= ndn_name_append(name, ce->hash->buf, ce->hash->length);
    if (ch->debug >= NDNL_FINE) {
        SyncNoteUri(diff_data->root, here, "starting", name);
    }
    // note, this fd belongs to sync_diff, not us
    struct ndn_closure *action = calloc(1, sizeof(*action));
    action->data = fd;
    action->p = &my_response;
    fd->action = action;
    
    struct ndn_charbuf *template = SyncGenInterest(NULL,
                                                   root->priv->syncScope,
                                                   base->priv->fetchLifetime,
                                                   -1, 1, NULL);
    
    res = ndn_express_interest(ndn, name, action, template);
    ndn_charbuf_destroy(&name);
    ndn_charbuf_destroy(&template);
    if (res < 0) {
        SyncNoteFailed(root, here, "ndn_express_interest failed", __LINE__);
        free(action);
        return -1;
    }
    return 1;
}

// my_add is called when sync_diff discovers a new name
// right now all we do is log it
static int
my_add(struct sync_diff_add_closure *ac, struct ndn_charbuf *name) {
    char *here = "sync_track.my_add";
    struct sync_diff_data *diff_data = ac->diff_data;
    struct ndns_handle *ch = diff_data->client_data;
    if (name == NULL) {
        // end of comparison, so fire off another round
        struct SyncRootStruct *root = diff_data->root;
        // struct ndn_charbuf *hash = ch->next_ce->hash;
        struct SyncHashCacheEntry *ce = ch->next_ce;
        int delay = 1000000;
        if (ch->debug >= NDNL_INFO) {
            char temp[1024];
            int pos = 0;
            ch->add_accum += diff_data->namesAdded;
            pos += snprintf(temp+pos, sizeof(temp)-pos, "added %jd, accum %jd",
                            (intmax_t) diff_data->namesAdded, (intmax_t) ch->add_accum);
            SyncNoteSimple(diff_data->root, here, temp);
        }
        if (diff_data->state == sync_diff_state_done) {
            // successful difference, so next_ce is covered
            ce->state |= SyncHashState_covered;
            delay = 10000;
            if (ch->last_ce == NULL) {
                // first time through, just accept the new entry
                ch->last_ce = ce;
                setCurrentHash(root, ce);
                ch->update_data->ceStart = ce;
            } else if (ch->namesToAdd != NULL && ch->namesToAdd->len > 0) {
                // need to update the entry
                ch->needUpdate = 1;
                ch->last_ce = ce;
                ch->update_data->ceStart = ce;
                delay = 1000;
            } else {
                // the last guess was not so good for the max, so revert
                ce = ch->last_ce;
                ch->next_ce = ce;
            }
        }
        start_round(ch, delay);
    } else {
        // accumulate the names
        if (ch->namesToAdd == NULL) {
            ch->namesToAdd = SyncAllocNameAccum(4);
        }
        SyncNameAccumAppend(ch->namesToAdd, SyncCopyName(name), 0);
        if (ch->debug >= NDNL_INFO)
            SyncNoteUri(diff_data->root, here, "adding", name);
        if (ch->nc != NULL) {
            // callback per name
            struct ndn_charbuf *lhash = ((ch->last_ce != NULL)
                                         ? ch->last_ce->hash : NULL);
            struct ndn_charbuf *rhash = ((ch->next_ce != NULL)
                                         ? ch->next_ce->hash : NULL);
            int res = ch->nc->callback(ch->nc, lhash, rhash, name);
            if (res < 0) {
                // stop the comparison here
                // TBD: anything else to do?
                return -1;
            }
        }
    }
    return 0;
}

static int
note_update_done(struct sync_done_closure *dc) {
    struct ndns_handle *ch = dc->data;
    struct sync_update_data *ud = dc->update_data;
    if (ch != NULL && ch->update_data == ud && ud != NULL && ud->done_closure == dc) {
        // passes sanity check
        static char *here = "sync_track.note_update_done";
        if (ud->ceStop != ud->ceStart && ud->ceStop != NULL) {
            // we have a new hash that is better
            setCurrentHash(ud->root, ud->ceStop);
            ud->ceStart = ud->ceStop;
            if (ch->debug >= NDNL_FINE)
                SyncNoteSimple(ud->root, here, "new hash set");
        } else {
            if (ch->debug >= NDNL_FINE)
                SyncNoteSimple(ud->root, here, "no new hash");
        }
        ch->needUpdate = 0;
        return 1;
    }
    return -1;
}

// the only client routine we might need is the logger
// there is no Repo in this application
static struct sync_plumbing_client_methods client_methods = {
    my_r_sync_msg, NULL, NULL, NULL, NULL, NULL
};

struct ndns_handle *
ndns_open(struct ndn *h,
          struct ndns_slice *slice,
          struct ndns_name_closure *nc,
          struct ndn_charbuf *rhash,
          struct ndn_charbuf *pname) {
    struct ndns_handle *ch = calloc(1, sizeof(*ch));
    struct SyncBaseStruct *base = NULL;
    struct SyncRootStruct *root = NULL;
    struct sync_plumbing *sync_plumbing = NULL;

    if (nc == NULL || nc->callback == NULL) return NULL;
    
    sync_plumbing = calloc(1, sizeof(*sync_plumbing));
    sync_plumbing->client_methods = &client_methods;
    sync_plumbing->ndn = h;
    sync_plumbing->sched = ndn_get_schedule(h);
    if (sync_plumbing->sched == NULL) {
        struct ndn_schedule *schedule;
        struct ndn_gettime *timer = calloc(1, sizeof(*timer));
        timer->descr[0]='S';
        timer->micros_per_base = 1000000;
        timer->gettime = &gettime;
        timer->data = h;
        schedule = ndn_schedule_create(h, timer);
        ndn_set_schedule(h, schedule);
        sync_plumbing->sched = schedule;
    }
    ch->sync_plumbing = sync_plumbing;
    ch->nc = nc;
    nc->ndns = ch;
    ch->ndn = h;
    
    // gen the closure for diff data
    struct sync_diff_data *diff_data = calloc(1, sizeof(*diff_data));
    struct sync_diff_get_closure *get_closure = calloc(1, sizeof(*get_closure));
    struct sync_diff_add_closure *add_closure = calloc(1, sizeof(*add_closure));
    diff_data->add_closure = add_closure;
    add_closure->diff_data = diff_data;
    add_closure->add = my_add;
    add_closure->data = ch;
    diff_data->get_closure = get_closure;
    get_closure->diff_data = diff_data;
    get_closure->get = my_get;
    get_closure->data = ch;
    
    diff_data->hashX = NULL;
    diff_data->hashY = NULL;
    diff_data->client_data = ch;
    ch->diff_data = diff_data;
    
    // gen the closure for update data
    struct sync_done_closure *done_closure = calloc(1, sizeof(*done_closure));
    struct sync_update_data *update_data = calloc(1, sizeof(*update_data));
    update_data->done_closure = done_closure;
    update_data->done_closure->done = note_update_done;
    update_data->done_closure->update_data = update_data;
    update_data->done_closure->data = ch;
    update_data->client_data = ch;
    ch->update_data = update_data;
    
    base = SyncNewBase(sync_plumbing);
    ch->base = base;
    struct sync_plumbing_sync_methods *sync_methods = ch->sync_plumbing->sync_methods;
    if (sync_methods!= NULL && sync_methods->sync_start != NULL) {
        // read the initial options, start life for the base
        sync_methods->sync_start(ch->sync_plumbing, NULL); 
    }
    
    // make the debug levels agree
    int debug = base->debug; // TBD: how to let client set this?
    if (debug < NDNL_WARNING) debug = NDNL_WARNING;
    base->debug = debug;
    ch->debug = debug;
    root = SyncAddRoot(base, base->priv->syncScope,
                       slice->topo, slice->prefix, NULL);
    ch->root = root;
    diff_data->root = root;
    update_data->root = root;
    
    // register the root advise interest listener
    struct ndn_charbuf *prefix = SyncCopyName(diff_data->root->topoPrefix);
    ndn_name_append_str(prefix, "\xC1.S.ra");
    ndn_name_append(prefix, root->sliceHash->buf, root->sliceHash->length);
    struct ndn_closure *action = NEW_STRUCT(1, ndn_closure);
    action->data = ch;
    action->p = &advise_interest_arrived;
    ch->registered = action;
    int res = ndn_set_interest_filter(h, prefix, action);
    ndn_charbuf_destroy(&prefix);
    if (res < 0) {
        noteErr2("ndns_open", "registration failed");
        ndns_close(&ch, rhash, pname);
        ch = NULL;
    } else {
        // start the very first round
        start_round(ch, 10);
    }
    return ch;
}

void
ndns_close(struct ndns_handle **sh,
           struct ndn_charbuf *rhash,
           struct ndn_charbuf *pname) {
    // Use this to shut down a ndns_handle and return the resources
    // This should work any legal state!
    // TBD: fill in pname argument
    if (sh != NULL) {
        struct ndns_handle *ch = *sh;
        *sh = NULL;
        if (ch != NULL) {
            struct SyncRootStruct *root = ch->root;
            
            struct ndn_closure *registered = ch->registered;
            if (registered != NULL) {
                // break the link, remove this particular registration
                registered->data = NULL;
                ndn_set_interest_filter_with_flags(ch->sync_plumbing->ndn,
                                                   root->topoPrefix,
                                                   registered,
                                                   0);
            }
            // cancel my looping event
            struct ndn_scheduled_event *ev = ch->ev;
            if (ev != NULL) {
                ch->ev = NULL;
                ev->evdata = NULL;
                ndn_schedule_cancel(ch->sync_plumbing->sched, ev);
            }
            // stop any differencing
            struct sync_diff_data *diff_data = ch->diff_data;
            if (diff_data != NULL) {
                // no more differencing
                ch->diff_data = NULL;
                free(diff_data->add_closure);
                diff_data->add_closure = NULL;
                free(diff_data->get_closure);
                diff_data->get_closure = NULL;
                sync_diff_stop(diff_data);
                free(diff_data);
            }
            // stop any updating
            struct sync_update_data *ud = ch->update_data;
            if (ud != NULL) {
                ch->update_data = NULL;
                free(ud->done_closure);
                ud->done_closure = NULL;
                sync_update_stop(ud);
                free(ud);
            }
            // stop any fetching
            while (ch->fetch_data != NULL) {
                free_fetch_data(ch, ch->fetch_data);
            }
            
            if (rhash != NULL) {
                // save the current root hash
                rhash->length = 0;
                if (root->currentHash != NULL)
                    ndn_charbuf_append_charbuf(rhash, root->currentHash);
            }
            SyncFreeNameAccumAndNames(ch->namesToAdd);
            // get rid of the root
            ch->root = NULL;
            SyncRemRoot(root);
            // XXX: what about the ch->hashSeen?
            // get rid of the base
            if (ch->base != NULL) {
                struct sync_plumbing_sync_methods *sm = ch->sync_plumbing->sync_methods;
                ch->base = NULL;
                if (sm != NULL && sm->sync_stop != NULL) {
                    sm->sync_stop(ch->sync_plumbing, NULL); 
                }
            }
            free(ch->sync_plumbing);
            free(ch);
            
        }
    }
}


