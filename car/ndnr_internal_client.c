/**
 * @file ndnr_internal_client.c
 * 
 * Part of ndnr -  NDNx Repository Daemon.
 *
 */

/*
 * Portions Copyright (C) 2013 Regents of the University of California.
 * 
 * Based on the CCNx C Library by PARC.
 * Copyright (C) 2011-2013 Palo Alto Research Center, Inc.
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
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/errno.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <ndn/ndn.h>
#include <ndn/charbuf.h>
#include <ndn/ndn_private.h>
#include <ndn/schedule.h>
#include <ndn/sockaddrutil.h>
#include <ndn/uri.h>
#include <ndn/keystore.h>
#include "ndnr_private.h"

#include "ndnr_internal_client.h"

#include "ndnr_forwarding.h"
#include "ndnr_io.h"
#include "ndnr_msg.h"
#include "ndnr_proto.h"
#include "ndnr_util.h"

static struct ndn_charbuf *
ndnr_init_service_ndnb(struct ndnr_handle *ndnr, struct ndn *h, const char *baseuri, int freshness)
{
    struct ndn_signing_params sp = NDN_SIGNING_PARAMS_INIT;
    struct ndn_charbuf *name = ndn_charbuf_create();
    struct ndn_charbuf *pubid = ndn_charbuf_create();
    struct ndn_charbuf *pubkey = ndn_charbuf_create();
    struct ndn_charbuf *keyid = ndn_charbuf_create();
    struct ndn_charbuf *cob = ndn_charbuf_create();
    int res;
    
    res = ndn_get_public_key(h, NULL, pubid, pubkey);
    if (res < 0) abort();
    ndn_name_from_uri(name, baseuri);
    ndn_charbuf_append_value(keyid, NDN_MARKER_CONTROL, 1);
    ndn_charbuf_append_string(keyid, ".M.K");
    ndn_charbuf_append_value(keyid, 0, 1);
    ndn_charbuf_append_charbuf(keyid, pubid);
    ndn_name_append(name, keyid->buf, keyid->length);
    ndn_create_version(h, name, 0, ndnr->starttime, ndnr->starttime_usec * 1000);
    sp.template_ndnb = ndn_charbuf_create();
    ndn_charbuf_append_tt(sp.template_ndnb, NDN_DTAG_SignedInfo, NDN_DTAG);
    ndn_charbuf_append_tt(sp.template_ndnb, NDN_DTAG_KeyLocator, NDN_DTAG);
    ndn_charbuf_append_tt(sp.template_ndnb, NDN_DTAG_KeyName, NDN_DTAG);
    ndn_charbuf_append_charbuf(sp.template_ndnb, name);
    ndn_charbuf_append_closer(sp.template_ndnb);
//    ndn_charbuf_append_tt(sp.template_ndnb, NDN_DTAG_PublisherPublicKeyDigest,
//                          NDN_DTAG);
//    ndn_charbuf_append_charbuf(sp.template_ndnb, pubid);
//    ndn_charbuf_append_closer(sp.template_ndnb);
    ndn_charbuf_append_closer(sp.template_ndnb);
    ndn_charbuf_append_closer(sp.template_ndnb);
    sp.sp_flags |= NDN_SP_TEMPL_KEY_LOCATOR;
    ndn_name_from_uri(name, "%00");
    sp.sp_flags |= NDN_SP_FINAL_BLOCK;
    sp.type = NDN_CONTENT_KEY;
    sp.freshness = freshness;
    res = ndn_sign_content(h, cob, name, &sp, pubkey->buf, pubkey->length);
    if (res != 0) abort();
    ndn_charbuf_destroy(&name);
    ndn_charbuf_destroy(&pubid);
    ndn_charbuf_destroy(&pubkey);
    ndn_charbuf_destroy(&keyid);
    ndn_charbuf_destroy(&sp.template_ndnb);
    return(cob);
}

/**
 * Common interest handler
 */
PUBLIC enum ndn_upcall_res
ndnr_answer_req(struct ndn_closure *selfp,
                 enum ndn_upcall_kind kind,
                 struct ndn_upcall_info *info)
{
    struct ndn_charbuf *msg = NULL;
    struct ndn_charbuf *name = NULL;
    struct ndn_charbuf *keylocator = NULL;
    struct ndn_charbuf *signed_info = NULL;
    struct ndn_charbuf *reply_body = NULL;
    struct ndnr_handle *ndnr = NULL;
    int res = 0;
    int morecomps = 0;
    const unsigned char *final_comp = NULL;
    size_t final_size = 0;
    
    switch (kind) {
        case NDN_UPCALL_FINAL:
            free(selfp);
            return(NDN_UPCALL_RESULT_OK);
        case NDN_UPCALL_INTEREST:
            break;
        case NDN_UPCALL_CONSUMED_INTEREST:
            return(NDN_UPCALL_RESULT_OK);
        default:
            return(NDN_UPCALL_RESULT_ERR);
    }
    ndnr = (struct ndnr_handle *)selfp->data;
    if (NDNSHOULDLOG(ndnr, LM_128, NDNL_FINE))
        ndnr_debug_ndnb(ndnr, __LINE__, "ndnr_answer_req", NULL,
                        info->interest_ndnb, info->pi->offset[NDN_PI_E]);
    morecomps = selfp->intdata & MORECOMPS_MASK;
    if ((info->pi->answerfrom & NDN_AOK_NEW) == 0 &&
        selfp->intdata != OP_SERVICE)
        return(NDN_UPCALL_RESULT_OK);
    if (info->matched_comps >= info->interest_comps->n)
        goto Bail;
    if ((selfp->intdata & OPER_MASK) != OP_SERVICE &&
        info->pi->prefix_comps != info->matched_comps + morecomps)
        goto Bail;
    if (morecomps == 1) {
        res = ndn_name_comp_get(info->interest_ndnb, info->interest_comps,
                                info->matched_comps,
                                &final_comp, &final_size);
        if (res < 0)
            goto Bail;
    }
    if ((selfp->intdata & MUST_VERIFY) != 0) {
        struct ndn_parsed_ContentObject pco = {0};
        // XXX - probably should check for message origin BEFORE verify
        res = ndn_parse_ContentObject(final_comp, final_size, &pco, NULL);
        if (res < 0) {
            ndnr_debug_ndnb(ndnr, __LINE__, "co_parse_failed", NULL,
                            info->interest_ndnb, info->pi->offset[NDN_PI_E]);
            goto Bail;
        }
        res = ndn_verify_content(info->h, final_comp, &pco);
        if (res != 0) {
            ndnr_debug_ndnb(ndnr, __LINE__, "co_verify_failed", NULL,
                            info->interest_ndnb, info->pi->offset[NDN_PI_E]);
            goto Bail;
        }
    }
    switch (selfp->intdata & OPER_MASK) {
        case OP_SERVICE:
            if (ndnr->service_ndnb == NULL)
                ndnr->service_ndnb = ndnr_init_service_ndnb(ndnr, info->h, NDNRID_LOCAL_URI, 600);
            if (ndn_content_matches_interest(
                    ndnr->service_ndnb->buf,
                    ndnr->service_ndnb->length,
                    1,
                    NULL,
                    info->interest_ndnb,
                    info->pi->offset[NDN_PI_E],
                    info->pi
                )) {
                ndn_put(info->h, ndnr->service_ndnb->buf,
                                 ndnr->service_ndnb->length);
                res = NDN_UPCALL_RESULT_INTEREST_CONSUMED;
                goto Finish;
            }
            // XXX this needs refactoring.
            if (ndnr->neighbor_ndnb == NULL)
                ndnr->neighbor_ndnb = ndnr_init_service_ndnb(ndnr, info->h, NDNRID_NEIGHBOR_URI, 5);
            if (ndn_content_matches_interest(
                    ndnr->neighbor_ndnb->buf,
                    ndnr->neighbor_ndnb->length,
                    1,
                    NULL,
                    info->interest_ndnb,
                    info->pi->offset[NDN_PI_E],
                    info->pi
                )) {
                ndn_put(info->h, ndnr->neighbor_ndnb->buf,
                                 ndnr->neighbor_ndnb->length);
                res = NDN_UPCALL_RESULT_INTEREST_CONSUMED;
                goto Finish;
            }
            if (ndn_content_matches_interest(
                                             ndnr->policy_link_cob->buf,
                                             ndnr->policy_link_cob->length,
                                             1,
                                             NULL,
                                             info->interest_ndnb,
                                             info->pi->offset[NDN_PI_E],
                                             info->pi
                                             )) {
                ndn_put(info->h, ndnr->policy_link_cob->buf,
                        ndnr->policy_link_cob->length);
                res = NDN_UPCALL_RESULT_INTEREST_CONSUMED;
                goto Finish;
            }
            goto Bail;
            break;
        default:
            // No other OP_xxx are supported here
            goto Bail;
    }
Bail:
    res = NDN_UPCALL_RESULT_ERR;
Finish:
    ndn_charbuf_destroy(&msg);
    ndn_charbuf_destroy(&name);
    ndn_charbuf_destroy(&keylocator);
    ndn_charbuf_destroy(&reply_body);
    ndn_charbuf_destroy(&signed_info);
    return(res);
}

static int
ndnr_internal_client_refresh(struct ndn_schedule *sched,
               void *clienth,
               struct ndn_scheduled_event *ev,
               int flags)
{
    struct ndnr_handle *ndnr = clienth;
    int microsec = 0;
    if ((flags & NDN_SCHEDULE_CANCEL) == 0 &&
          ndnr->internal_client != NULL &&
          ndnr->internal_client_refresh == ev) {
        microsec = ndn_process_scheduled_operations(ndnr->internal_client);
        if (microsec > ev->evint)
            microsec = ev->evint;
    }
    if (microsec <= 0 && ndnr->internal_client_refresh == ev)
        ndnr->internal_client_refresh = NULL;
    return(microsec);
}

#define NDNR_ID_TEMPL "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"

PUBLIC void
ndnr_uri_listen(struct ndnr_handle *ndnr, struct ndn *ndn, const char *uri,
                ndn_handler p, intptr_t intdata)
{
    struct ndn_charbuf *name;
    struct ndn_charbuf *uri_modified = NULL;
    struct ndn_closure *closure;
    struct ndn_indexbuf *comps;
    const unsigned char *comp;
    size_t comp_size;
    size_t offset;
    
    name = ndn_charbuf_create();
    ndn_name_from_uri(name, uri);
    comps = ndn_indexbuf_create();
    if (ndn_name_split(name, comps) < 0)
        abort();
    if (ndn_name_comp_get(name->buf, comps, 1, &comp, &comp_size) >= 0) {
        if (comp_size == 32 && 0 == memcmp(comp, NDNR_ID_TEMPL, 32)) {
            /* Replace placeholder with our ndnr_id */
            offset = comp - name->buf;
            memcpy(name->buf + offset, ndnr->ndnr_id, 32);
            uri_modified = ndn_charbuf_create();
            ndn_uri_append(uri_modified, name->buf, name->length, 1);
            uri = (char *)uri_modified->buf;
        }
    }
    closure = calloc(1, sizeof(*closure));
    closure->p = p;
    closure->data = ndnr;
    closure->intdata = intdata;
    ndn_set_interest_filter(ndn, name, closure);
    ndn_charbuf_destroy(&name);
    ndn_charbuf_destroy(&uri_modified);
    ndn_indexbuf_destroy(&comps);
}

/*
 * This is used to shroud the contents of the keystore, which mainly serves
 * to add integrity checking and defense against accidental misuse.
 * The file permissions serve for restricting access to the private keys.
 */
#ifndef NDNR_KEYSTORE_PASS
#define NDNR_KEYSTORE_PASS "Th1s 1s n0t 8 g00d R3p0s1t0ry p8ssw0rd!"
#endif

/**
 *  Create the repository keystore if necessary,
 *  and load it into the client handle h.
 *
 *  It is permitted for h to be NULL to skip the load.
 *  @returns -1 if there were problems.
 */
 
int
ndnr_init_repo_keystore(struct ndnr_handle *ndnr, struct ndn *h)
{
    struct ndn_charbuf *temp = NULL;
    struct ndn_charbuf *culprit = NULL;
    struct stat statbuf;
    int res = -1;
    char *keystore_path = NULL;
    struct ndn_signing_params sp = NDN_SIGNING_PARAMS_INIT;
    
    temp = ndn_charbuf_create();
    culprit = temp;
    ndn_charbuf_putf(temp, "%s/", ndnr->directory);
    res = stat(ndn_charbuf_as_string(temp), &statbuf);
    if (res == -1)
        goto Finish;
    if ((statbuf.st_mode & S_IFDIR) == 0) {
        res = -1;
        errno = ENOTDIR;
        goto Finish;
    }
    ndn_charbuf_putf(temp, "ndnx_repository_keystore");
    keystore_path = strdup(ndn_charbuf_as_string(temp));
    res = stat(keystore_path, &statbuf);
    
    if (res == 0 && h != NULL)
        res = ndn_load_default_key(h, keystore_path, NDNR_KEYSTORE_PASS);
    if (res >= 0) {
        culprit = NULL;
        goto Finish;
    }
    /* No stored keystore that we can access. Create one if we can.*/
    res = ndn_keystore_file_init(keystore_path, NDNR_KEYSTORE_PASS, "Repository", 0, 0);
    if (res != 0) {
        res = -1;
        goto Finish;
    }
    if (NDNSHOULDLOG(ndnr, keystore, NDNL_WARNING))
        ndnr_msg(ndnr, "New repository private key saved in %s", keystore_path);
    if (h != NULL)
        res = ndn_load_default_key(h, keystore_path, NDNR_KEYSTORE_PASS);
Finish:
    if (res >= 0 && h != NULL)
        res = ndn_chk_signing_params(h, NULL, &sp, NULL, NULL, NULL, NULL);
    if (res >= 0 && h != NULL) {
        memcpy(ndnr->ndnr_id, sp.pubid, sizeof(ndnr->ndnr_id));
        if (ndnr->ndnr_keyid == NULL)
            ndnr->ndnr_keyid = ndn_charbuf_create();
        else
            ndnr->ndnr_keyid->length = 0;
        ndn_charbuf_append_value(ndnr->ndnr_keyid, NDN_MARKER_CONTROL, 1);
        ndn_charbuf_append_string(ndnr->ndnr_keyid, ".M.K");
        ndn_charbuf_append_value(ndnr->ndnr_keyid, 0, 1);
        ndn_charbuf_append(ndnr->ndnr_keyid, ndnr->ndnr_id, sizeof(ndnr->ndnr_id));
    }
    if (res < 0) {
        ndnr->running = -1; /* Make note of init failure */
        if (culprit != NULL)
            ndnr_msg(ndnr, "Error accessing keystore - %s: %s\n",
                     strerror(errno), ndn_charbuf_as_string(temp));
    }
    ndn_charbuf_destroy(&temp);
    if (keystore_path != NULL)
        free(keystore_path);
    return(res);
}

static int
post_face_notice(struct ndnr_handle *ndnr, unsigned filedesc)
{
    struct fdholder *fdholder = ndnr_r_io_fdholder_from_fd(ndnr, filedesc);
    struct ndn_charbuf *msg = ndn_charbuf_create();
    int res = -1;
    int port;
    
    // XXX - text version for trying out stream stuff - replace with ndnb
    if (fdholder == NULL)
        ndn_charbuf_putf(msg, "destroyface(%u);\n", filedesc);
    else {
        ndn_charbuf_putf(msg, "newface(%u, 0x%x", filedesc, fdholder->flags);
        if (fdholder->name->length != 0 &&
            (fdholder->flags & (NDNR_FACE_INET | NDNR_FACE_INET6)) != 0) {
            ndn_charbuf_putf(msg, ", ");
            port = ndn_charbuf_append_sockaddr(msg, (struct sockaddr *)fdholder->name->buf);
            if (port < 0)
                msg->length--;
            else if (port > 0)
                ndn_charbuf_putf(msg, ":%d", port);
        }
        ndn_charbuf_putf(msg, ");\n", filedesc);
    }
    res = ndn_seqw_write(ndnr->notice, msg->buf, msg->length);
    ndn_charbuf_destroy(&msg);
    return(res);
}

static int
ndnr_notice_push(struct ndn_schedule *sched,
               void *clienth,
               struct ndn_scheduled_event *ev,
               int flags)
{
    struct ndnr_handle *ndnr = clienth;
    struct ndn_indexbuf *chface = NULL;
    int i = 0;
    int j = 0;
    int microsec = 0;
    int res = 0;
    
    if ((flags & NDN_SCHEDULE_CANCEL) == 0 &&
            ndnr->notice != NULL &&
            ndnr->notice_push == ev &&
            ndnr->chface != NULL) {
        chface = ndnr->chface;
        ndn_seqw_batch_start(ndnr->notice);
        for (i = 0; i < chface->n && res != -1; i++)
            res = post_face_notice(ndnr, chface->buf[i]);
        ndn_seqw_batch_end(ndnr->notice);
        for (j = 0; i < chface->n; i++, j++)
            chface->buf[j] = chface->buf[i];
        chface->n = j;
        if (res == -1)
            microsec = 3000;
    }
    if (microsec <= 0)
        ndnr->notice_push = NULL;
    return(microsec);
}

/**
 * Called by ndnr when a fdholder undergoes a substantive status change that
 * should be reported to interested parties.
 *
 * In the destroy case, this is called from the hash table finalizer,
 * so it shouldn't do much directly.  Inspecting the fdholder is OK, though.
 */
void
ndnr_face_status_change(struct ndnr_handle *ndnr, unsigned filedesc)
{
    struct ndn_indexbuf *chface = ndnr->chface;
    if (chface != NULL) {
        ndn_indexbuf_set_insert(chface, filedesc);
        if (ndnr->notice_push == NULL)
            ndnr->notice_push = ndn_schedule_event(ndnr->sched, 2000,
                                                   ndnr_notice_push,
                                                   NULL, 0);
    }
}

int
ndnr_internal_client_start(struct ndnr_handle *ndnr)
{
    if (ndnr->internal_client != NULL)
        return(-1);
    if (ndnr->face0 == NULL)
        abort();
    ndnr->internal_client = ndn_create();
    if (ndnr_init_repo_keystore(ndnr, ndnr->internal_client) < 0) {
        ndn_destroy(&ndnr->internal_client);
        return(-1);
    }
    ndnr->internal_client_refresh = ndn_schedule_event(ndnr->sched, 50000,
                         ndnr_internal_client_refresh,
                         NULL, NDN_INTEREST_LIFETIME_MICROSEC);
    return(0);
}

void
ndnr_internal_client_stop(struct ndnr_handle *ndnr)
{
    ndnr->notice = NULL; /* ndn_destroy will free */
    if (ndnr->notice_push != NULL)
        ndn_schedule_cancel(ndnr->sched, ndnr->notice_push);
    ndn_indexbuf_destroy(&ndnr->chface);
    ndn_destroy(&ndnr->internal_client);
    ndn_charbuf_destroy(&ndnr->service_ndnb);
    ndn_charbuf_destroy(&ndnr->neighbor_ndnb);
    if (ndnr->internal_client_refresh != NULL)
        ndn_schedule_cancel(ndnr->sched, ndnr->internal_client_refresh);
}

// XXX - these are very similar to the above.
// If we keep multiple internal handles around, this will need refactoring.


static int
ndnr_direct_client_refresh(struct ndn_schedule *sched,
               void *clienth,
               struct ndn_scheduled_event *ev,
               int flags)
{
    struct ndnr_handle *ndnr = clienth;
    int microsec = 0;
    if ((flags & NDN_SCHEDULE_CANCEL) == 0 &&
          ndnr->direct_client != NULL &&
          ndnr->direct_client_refresh == ev) {
        microsec = ndn_process_scheduled_operations(ndnr->direct_client);
        // XXX - This is not really right, since an incoming request can cause us to need to reschedule this event.
        if NDNSHOULDLOG(ndnr, refresh, NDNL_FINEST)
            ndnr_msg(ndnr, "direct_client_refresh %d in %d usec",
                     ndn_get_connection_fd(ndnr->direct_client), microsec);
        if (microsec > ev->evint)
            microsec = ev->evint;
        if (microsec == 0)
            microsec = NDN_INTEREST_LIFETIME_MICROSEC;
    }
    if (microsec <= 0 && ndnr->direct_client_refresh == ev)
        ndnr->direct_client_refresh = NULL;
    return(microsec);
}

int
ndnr_direct_client_start(struct ndnr_handle *ndnr)
{
    ndnr->direct_client = ndn_create();
    if (ndnr_init_repo_keystore(ndnr, ndnr->direct_client) < 0) {
        ndn_destroy(&ndnr->direct_client);
        return(-1);
    }
    ndnr->direct_client_refresh = ndn_schedule_event(ndnr->sched, 50000,
                         ndnr_direct_client_refresh,
                         NULL, NDN_INTEREST_LIFETIME_MICROSEC);
    return(0);
}

void
ndnr_direct_client_stop(struct ndnr_handle *ndnr)
{
    if (ndnr->notice_push != NULL)
        ndn_schedule_cancel(ndnr->sched, ndnr->notice_push);
    ndn_indexbuf_destroy(&ndnr->chface);
    ndn_destroy(&ndnr->direct_client);
    ndn_charbuf_destroy(&ndnr->service_ndnb);
    ndn_charbuf_destroy(&ndnr->neighbor_ndnb);
    if (ndnr->direct_client_refresh != NULL)
        ndn_schedule_cancel(ndnr->sched, ndnr->direct_client_refresh);
}

