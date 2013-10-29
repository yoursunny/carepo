/**
 * @file ndnr_sync.c
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

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/types.h>

#include <ndn/btree.h>
#include <ndn/btree_content.h>
#include <ndn/ndn.h>
#include <ndn/charbuf.h>
#include <ndn/indexbuf.h>
#include <ndn/schedule.h>

#include <sync/SyncBase.h>

#include "ndnr_private.h"

#include "ndnr_dispatch.h"
#include "ndnr_io.h"
#include "ndnr_link.h"
#include "ndnr_msg.h"
#include "ndnr_proto.h"
#include "ndnr_store.h"
#include "ndnr_sync.h"
#include "ndnr_util.h"

#include <sync/sync_plumbing.h>

#ifndef NDNLINT

/* Preliminary implementation - algorithm may change */

PUBLIC uintmax_t
ndnr_accession_encode(struct ndnr_handle *ndnr, ndnr_accession a)
{
    return(a);
}

PUBLIC ndnr_accession
ndnr_accession_decode(struct ndnr_handle *ndnr, uintmax_t encoded)
{
    return(encoded);
}

PUBLIC int
ndnr_accession_compare(struct ndnr_handle *ndnr, ndnr_accession x, ndnr_accession y)
{
    if (x > y) return 1;
    if (x == y) return 0;
    if (x < y) return -1;
    return NDNR_NOT_COMPARABLE;
}

PUBLIC uintmax_t
ndnr_hwm_encode(struct ndnr_handle *ndnr, ndnr_hwm hwm)
{
    return(hwm);
}

PUBLIC ndnr_hwm
ndnr_hwm_decode(struct ndnr_handle *ndnr, uintmax_t encoded)
{
    return(encoded);
}

PUBLIC int
ndnr_acc_in_hwm(struct ndnr_handle *ndnr, ndnr_accession a, ndnr_hwm hwm)
{
    return(a <= hwm);
}

PUBLIC ndnr_hwm
ndnr_hwm_update(struct ndnr_handle *ndnr, ndnr_hwm hwm, ndnr_accession a)
{
    return(a <= hwm ? hwm : a);
}

PUBLIC ndnr_hwm
ndnr_hwm_merge(struct ndnr_handle *ndnr, ndnr_hwm x, ndnr_hwm y)
{
    return(x < y ? y : x);
}

PUBLIC int
ndnr_hwm_compare(struct ndnr_handle *ndnr, ndnr_hwm x, ndnr_hwm y)
{
    if (x > y) return 1;
    if (x == y) return 0;
    if (x < y) return -1;
    return NDNR_NOT_COMPARABLE;
}
#endif

/**
 * A wrapper for ndnr_msg that takes a sync_plumbing instead of ndnr_handle
 */
PUBLIC void
r_sync_msg(struct sync_plumbing *sdd,
           const char *fmt, ...)
{
    struct ndnr_handle *ndnr = (struct ndnr_handle *)sdd->client_data;
    va_list ap;
    va_start(ap, fmt);
    ndnr_vmsg(ndnr, fmt, ap);
    va_end(ap);
}

PUBLIC int
r_sync_fence(struct sync_plumbing *sdd,
             uint64_t seq_num)
{
    struct ndnr_handle *h = (struct ndnr_handle *)sdd->client_data;
    // TODO: this needs to do something more interesting.
    ndnr_msg(h, "r_sync_fence: seq_num %ju", seq_num);
    h->notify_after = (ndnr_accession) seq_num;
    return (0);
}

/**
 * A wrapper for the sync_notify method that takes a content entry.
 */
PUBLIC int
r_sync_notify_content(struct ndnr_handle *ndnr, int e, struct content_entry *content)
{
    struct sync_plumbing *sync_plumbing = ndnr->sync_plumbing;
    int res;
    ndnr_accession acc = NDNR_NULL_ACCESSION;

    if (sync_plumbing == NULL)
        return (0);

    if (content == NULL) {
        if (e == 0)
            abort();
        res = sync_plumbing->sync_methods->sync_notify(ndnr->sync_plumbing, NULL, e, 0);
        if (res < 0)
            ndnr_msg(ndnr, "sync_notify(..., NULL, %d, 0) returned %d, expected >= 0",
                     e, res);
    }
    else {
        struct ndn_charbuf *cb = r_util_charbuf_obtain(ndnr);

        acc = r_store_content_accession(ndnr, content);
        if (acc == NDNR_NULL_ACCESSION) {
            ndnr_debug_content(ndnr, __LINE__, "r_sync_notify_content - not yet stable", NULL, content);
            return(0);
        }
        /* This must get the full name, including digest. */
        ndn_name_init(cb);
        res = r_store_name_append_components(cb, ndnr, content, 0, -1);
        if (res < 0) abort();
        if (NDNSHOULDLOG(ndnr, r_sync_notify_content, NDNL_FINEST))
            ndnr_debug_content(ndnr, __LINE__, "r_sync_notify_content", NULL, content);
        res = sync_plumbing->sync_methods->sync_notify(ndnr->sync_plumbing, cb, e, acc);
        r_util_charbuf_release(ndnr, cb);
    }
    if (NDNSHOULDLOG(ndnr, r_sync_notify_content, NDNL_FINEST))
        ndnr_msg(ndnr, "sync_notify(..., %d, 0x%jx, ...) returned %d",
                 e, ndnr_accession_encode(ndnr, acc), res);
    if (e == 0 && res == -1) {
        // TODO: wrong in new sync interface terms
        //r_sync_notify_after(ndnr, NDNR_MAX_ACCESSION); // XXXXXX should be hwm
    }
    return(res);
}

/**
 *  State for an ongoing sync enumeration.
 */
struct sync_enumeration_state {
    int magic; /**< for sanity check - should be se_cookie */
    int index; /**< Index into ndnr->active_enum */
    ndnr_cookie cookie; /**< Resumption point */
    struct ndn_parsed_interest parsed_interest;
    struct ndn_charbuf *interest;
    struct ndn_indexbuf *comps;
};
static const int se_cookie = __LINE__;

static struct sync_enumeration_state *
cleanup_se(struct ndnr_handle *ndnr, struct sync_enumeration_state *md)
{
    if (md != NULL && md->magic == se_cookie) {
        int i = md->index;
        if (NDNSHOULDLOG(ndnr, cleanup_se, NDNL_FINEST))
            ndnr_msg(ndnr, "sync_enum_cleanup %d", i);
        if (0 < i && i < NDNR_MAX_ENUM)
            ndnr->active_enum[i] = NDNR_NULL_ACCESSION;
        ndn_indexbuf_destroy(&md->comps);
        ndn_charbuf_destroy(&md->interest);
        free(md);
    }
    return(NULL);
}

static int
r_sync_enumerate_action(struct ndn_schedule *sched,
    void *clienth,
    struct ndn_scheduled_event *ev,
    int flags)
{
    struct ndnr_handle *ndnr = clienth;
    struct sync_enumeration_state *md = NULL;
    struct content_entry *content = NULL;
    struct ndn_btree_node *leaf = NULL;
    struct ndn_charbuf *interest = NULL;
    struct ndn_parsed_interest *pi = NULL;
    struct ndn_charbuf *scratch = NULL;
    struct ndn_charbuf *flat = NULL;
    int ndx;
    int res;
    int try;
    int matches;
    
    md = ev->evdata;
    if (md->magic != se_cookie || md->index >= NDNR_MAX_ENUM) abort();
    if ((flags & NDN_SCHEDULE_CANCEL) != 0) {
        ev->evdata = cleanup_se(ndnr, md);
        return(0);
    }
    pi = &md->parsed_interest;
    interest = md->interest;
    /*
     * Recover starting point from either cookie or accession.
     *
     * The accession number might not be available yet (but we try to avoid
     * suspending in such a case).
     * The cookie might go away, but only if the content has been accessioned.
     */
    content = r_store_content_from_cookie(ndnr, md->cookie);
    if (content == NULL && md->cookie != 0)
        content = r_store_content_from_accession(ndnr, ndnr->active_enum[md->index]);
    for (try = 0, matches = 0; content != NULL; try++) {
        if (scratch == NULL)
            scratch = ndn_charbuf_create();
        flat = r_store_content_flatname(ndnr, content);
        res = ndn_btree_lookup(ndnr->btree, flat->buf, flat->length, &leaf);
        if (NDN_BT_SRCH_FOUND(res) == 0) {
            ndnr_debug_content(ndnr, __LINE__, "impossible", NULL, content);
            break;
        }
        ndx = NDN_BT_SRCH_INDEX(res);
        res = ndn_btree_match_interest(leaf, ndx, interest->buf, pi, scratch);
        if (res == -1) {
            ndnr_debug_content(ndnr, __LINE__, "impossible", NULL, content);
            break;
        }
        if (res == 1) {
            res = r_sync_notify_content(ndnr, md->index, content);
            matches++;
            if (res == -1) {
                if (NDNSHOULDLOG(ndnr, r_sync_enumerate_action, NDNL_FINEST))
                    ndnr_debug_content(ndnr, __LINE__, "r_sync_enumerate_action", NULL,
                                       content);
                ev->evdata = cleanup_se(ndnr, md);
                ndn_charbuf_destroy(&scratch);
                return(0);
            }
        }
        content = r_store_content_next(ndnr, content);
        if (content != NULL &&
            !r_store_content_matches_interest_prefix(ndnr, content,
                                                     interest->buf,
                                                     interest->length))
            content = NULL;
        if (content != NULL) {
            md->cookie = r_store_content_cookie(ndnr, content);
            ndnr->active_enum[md->index] = r_store_content_accession(ndnr, content);
            if (ndnr->active_enum[md->index] != NDNR_NULL_ACCESSION && 
                (matches >= 8 || try >= 200)) { // XXX - these numbers need tuning
                ndn_charbuf_destroy(&scratch);
                return(300);
            }
        }
    }
    r_sync_notify_content(ndnr, md->index, NULL);
    ev->evdata = cleanup_se(ndnr, md);
    ndn_charbuf_destroy(&scratch);
    return(0);
}

/**
 * Request that a SyncNotifyContent call be made for each content object
 *  in the repository that matches the interest.
 *
 * If SyncNotifyContent returns -1 the active enumeration will be cancelled.
 *
 * When there are no more matching objects, SyncNotifyContent will be called
 *  passing NULL for name.
 *
 * Content objects that arrive during an enumeration may or may not be included
 *  in that enumeration.
 *
 *  @returns -1 for error, or an enumeration number which will also be passed
 *      in the SyncNotifyContent
 */
PUBLIC int
r_sync_enumerate(struct sync_plumbing *sdd,
                 struct ndn_charbuf *interest)
{
    struct ndnr_handle *ndnr = (struct ndnr_handle *)sdd->client_data;
    int ans = -1;
    int i;
    int res;
    struct ndn_indexbuf *comps = NULL;
    struct ndn_parsed_interest parsed_interest = {0};
    struct ndn_parsed_interest *pi = &parsed_interest;
    struct content_entry *content = NULL;
    struct sync_enumeration_state *md = NULL;
    
    if (NDNSHOULDLOG(ndnr, r_sync_enumerate, NDNL_FINEST))
        ndnr_debug_ndnb(ndnr, __LINE__, "sync_enum_start", NULL,
                        interest->buf, interest->length);
    comps = ndn_indexbuf_create();
    res = ndn_parse_interest(interest->buf, interest->length, pi, comps);
    if (res < 0) {
        ndnr_debug_ndnb(ndnr, __LINE__, "bogus r_sync_enumerate request", NULL,
                        interest->buf, interest->length);
        if (NDNSHOULDLOG(ndnr, r_sync_enumerate, NDNL_FINEST)) {
            struct ndn_charbuf *temp = ndn_charbuf_create();
            ndn_charbuf_putf(temp, "interest_dump ");
            for (i = 0; i < interest->length; i++)
                ndn_charbuf_putf(temp, "%02X", interest->buf[i]);
            ndnr_msg(ndnr, ndn_charbuf_as_string(temp));
            ndn_charbuf_destroy(&temp);
        }
        goto Bail;
    }
    /* 0 is for notify_after - don't allocate it here. */
    for (i = 1; i < NDNR_MAX_ENUM; i++) {
        if (ndnr->active_enum[i] == NDNR_NULL_ACCESSION) {
            ans = i;
            ndnr->active_enum[ans] = NDNR_MAX_ACCESSION; /* for no-match case */
            break;
        }
    }
    if (ans < 0) {
        if (NDNSHOULDLOG(ndnr, r_sync_enumerate, NDNL_WARNING))
            ndnr_msg(ndnr, "sync_enum - Too many active enumerations!", ans);
        goto Bail;
    }
    content = r_store_find_first_match_candidate(ndnr, interest->buf, pi);
    if (content == NULL) {
        if (NDNSHOULDLOG(ndnr, r_sync_enumerate, NDNL_FINE))
            ndnr_debug_ndnb(ndnr, __LINE__, "sync_enum_nomatch", NULL,
                        interest->buf, interest->length);
    }
    else if (r_store_content_matches_interest_prefix(ndnr,
           content, interest->buf, interest->length)) {
        ndnr->active_enum[ans] = r_store_content_accession(ndnr, content);
        if (NDNSHOULDLOG(ndnr, r_sync_enumerate, NDNL_FINEST))
            ndnr_msg(ndnr, "sync_enum id=%d starting accession=0x%jx",
                     ans, ndnr_accession_encode(ndnr, ndnr->active_enum[ans]));
    }
    
    /* Set up the state for r_sync_enumerate_action */
    md = calloc(1, sizeof(*md));
    if (md == NULL) { ndnr->active_enum[ans] = NDNR_NULL_ACCESSION; ans = -1; goto Bail; }
    md->magic = se_cookie;
    md->cookie = content == NULL ? 0 : r_store_content_cookie(ndnr, content);
    md->index = ans;
    md->interest = ndn_charbuf_create();
    if (md->interest == NULL) goto Bail;
    ndn_charbuf_append(md->interest, interest->buf, interest->length);
    md->parsed_interest = parsed_interest;
    md->comps = comps;
    comps = NULL;

    /* All the upcalls happen in r_sync_enumerate_action. */
    
    if (NULL != ndn_schedule_event(ndnr->sched, 123, r_sync_enumerate_action, md, 0))
        md = NULL;
    
Bail:
    if (md != NULL) {
        ans = -1;
        md = cleanup_se(ndnr, md);
    }
    ndn_indexbuf_destroy(&comps);
    if (NDNSHOULDLOG(ndnr, r_sync_enumerate, NDNL_FINEST))
        ndnr_msg(ndnr, "sync_enum %d", ans);
    return(ans);
}

PUBLIC int
r_sync_lookup(struct sync_plumbing *sdd,
              struct ndn_charbuf *interest,
              struct ndn_charbuf *content_ndnb)
{
    struct ndnr_handle *ndnr = (struct ndnr_handle *)sdd->client_data;
    return(r_lookup(ndnr, interest, content_ndnb));
}

PUBLIC int
r_lookup(struct ndnr_handle *ndnr,
                  struct ndn_charbuf *interest,
                  struct ndn_charbuf *content_ndnb)
{
    int ans = -1;
    struct ndn_indexbuf *comps = r_util_indexbuf_obtain(ndnr);
    struct ndn_parsed_interest parsed_interest = {0};
    struct ndn_parsed_interest *pi = &parsed_interest;
    struct content_entry *content = NULL;
    
    if (NULL == comps || (ndn_parse_interest(interest->buf, interest->length, pi, comps) < 0))
        abort();
    content = r_store_lookup(ndnr, interest->buf, pi, comps);
    if (content != NULL) {
        ans = 0;
        if (content_ndnb != NULL) {
            const unsigned char *base = r_store_content_base(ndnr, content);
            size_t size = r_store_content_size(ndnr, content);
            if (base == NULL) {
                ndnr_debug_ndnb(ndnr, __LINE__, "r_sync_lookup null content base", NULL,
                                interest->buf, interest->length);
                ans = -1;
            } else
                ndn_charbuf_append(content_ndnb, base, size);
        }
    }
    r_util_indexbuf_release(ndnr, comps);
    return(ans);
}
/**
 * Called when a content object is received by sync and needs to be
 * committed to stable storage by the repo.
 */
PUBLIC enum ndn_upcall_res
r_sync_upcall_store(struct sync_plumbing *sdd,
                    enum ndn_upcall_kind kind,
                    struct ndn_upcall_info *info)
{
    struct ndnr_handle *ndnr = (struct ndnr_handle *)sdd->client_data;
    enum ndn_upcall_res ans = NDN_UPCALL_RESULT_OK;
    const unsigned char *ndnb = NULL;
    size_t ndnb_size = 0;
    struct content_entry *content;
    
    if (kind != NDN_UPCALL_CONTENT)
        return(NDN_UPCALL_RESULT_ERR);
    
    ndnb = info->content_ndnb;
    ndnb_size = info->pco->offset[NDN_PCO_E];
    
    content = process_incoming_content(ndnr, r_io_fdholder_from_fd(ndnr, ndn_get_connection_fd(info->h)),
                                       (void *)ndnb, ndnb_size, NULL);
    if (content == NULL) {
        ndnr_msg(ndnr, "r_sync_upcall_store: failed to process incoming content");
        return(NDN_UPCALL_RESULT_ERR);
    }
    // XXX - here we need to check if this is something we *should* be storing, according to our policy
    if ((r_store_content_flags(content) & NDN_CONTENT_ENTRY_STABLE) == 0) {
        r_store_commit_content(ndnr, content);
        if (NDNSHOULDLOG(ndnr, r_sync_upcall_store, NDNL_FINE))
            ndnr_debug_content(ndnr, __LINE__, "content_stored",
                               r_io_fdholder_from_fd(ndnr, ndnr->active_out_fd),
                               content);
    }        
    r_proto_initiate_key_fetch(ndnr, ndnb, info->pco, 0,
                               r_store_content_cookie(ndnr, content));

    return(ans);
}

/**
 * Called when a content object has been constructed locally by sync
 * and needs to be committed to stable storage by the repo.
 * returns 0 for success, -1 for error.
 */

PUBLIC int
r_sync_local_store(struct sync_plumbing *sdd,
                   struct ndn_charbuf *content_cb)
{
    struct ndnr_handle *ndnr = (struct ndnr_handle *)sdd->client_data;
    struct content_entry *content = NULL;
    
    // pretend it came from the internal client, for statistics gathering purposes
    content = process_incoming_content(ndnr, ndnr->face0,
                                       (void *)content_cb->buf, content_cb->length, NULL);
    if (content == NULL) {
        ndnr_msg(ndnr, "r_sync_local_store: failed to process content");
        return(-1);
    }
    // XXX - we assume we must store things from sync independent of policy
    // XXX - sync may want notification, or not, at least for now.
    if ((r_store_content_flags(content) & NDN_CONTENT_ENTRY_STABLE) == 0) {
        r_store_commit_content(ndnr, content);
        if (NDNSHOULDLOG(ndnr, r_sync_local_store, NDNL_FINE))
            ndnr_debug_content(ndnr, __LINE__, "content_stored_local",
                               r_io_fdholder_from_fd(ndnr, ndnr->active_out_fd),
                               content);
    }
    return(0);
}
