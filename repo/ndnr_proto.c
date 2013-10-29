/**
 * @file ndnr_proto.c
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
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <sys/errno.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <ndn/ndn.h>
#include <ndn/charbuf.h>
#include <ndn/ndn_private.h>
#include <ndn/hashtb.h>
#include <ndn/schedule.h>
#include <ndn/sockaddrutil.h>
#include <ndn/uri.h>
#include <ndn/coding.h>
#include <sync/SyncBase.h>
#include "ndnr_private.h"

#include "ndnr_proto.h"

#include "ndnr_dispatch.h"
#include "ndnr_forwarding.h"
#include "ndnr_init.h"
#include "ndnr_io.h"
#include "ndnr_msg.h"
#include "ndnr_sendq.h"
#include "ndnr_store.h"
#include "ndnr_sync.h"
#include "ndnr_util.h"

#define NDNR_MAX_RETRY 5

static enum ndn_upcall_res
r_proto_start_write(struct ndn_closure *selfp,
                    enum ndn_upcall_kind kind,
                    struct ndn_upcall_info *info,
                    int marker_comp);

static enum ndn_upcall_res
r_proto_start_write_checked(struct ndn_closure *selfp,
                            enum ndn_upcall_kind kind,
                            struct ndn_upcall_info *info,
                            int marker_comp);

static enum ndn_upcall_res
r_proto_begin_enumeration(struct ndn_closure *selfp,
                          enum ndn_upcall_kind kind,
                          struct ndn_upcall_info *info,
                          int marker_comp);

static enum ndn_upcall_res
r_proto_continue_enumeration(struct ndn_closure *selfp,
                             enum ndn_upcall_kind kind,
                             struct ndn_upcall_info *info,
                             int marker_comp);

static enum ndn_upcall_res
r_proto_bulk_import(struct ndn_closure *selfp,
                             enum ndn_upcall_kind kind,
                             struct ndn_upcall_info *info,
                             int marker_comp);
static int
name_comp_equal_prefix(const unsigned char *data,
                    const struct ndn_indexbuf *indexbuf,
                    unsigned int i, const void *buf, size_t length);

PUBLIC enum ndn_upcall_res
r_proto_answer_req(struct ndn_closure *selfp,
                 enum ndn_upcall_kind kind,
                 struct ndn_upcall_info *info)
{
    struct ndn_charbuf *msg = NULL;
    struct ndn_charbuf *name = NULL;
    struct ndn_charbuf *keylocator = NULL;
    struct ndn_charbuf *signed_info = NULL;
    struct ndn_charbuf *reply_body = NULL;
    struct ndnr_handle *ndnr = NULL;
    struct content_entry *content = NULL;
    int res = 0;
    int ncomps;
    int marker_comp;
    // struct ndn_signing_params sp = NDN_SIGNING_PARAMS_INIT;
    
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
        ndnr_debug_ndnb(ndnr, __LINE__, "r_proto_answer_req", NULL,
                        info->interest_ndnb, info->pi->offset[NDN_PI_E]);
    
    content = r_store_lookup(ndnr, info->interest_ndnb, info->pi, info->interest_comps);
    if (content != NULL) {
        struct fdholder *fdholder = r_io_fdholder_from_fd(ndnr, ndn_get_connection_fd(info->h));
        if (fdholder != NULL)
            r_sendq_face_send_queue_insert(ndnr, r_io_fdholder_from_fd(ndnr, ndn_get_connection_fd(info->h)), content);
        res = NDN_UPCALL_RESULT_INTEREST_CONSUMED;
        goto Finish;
    }
    /* commands will potentially generate new content, test if new content is ok */
    if ((info->pi->answerfrom & NDN_AOK_NEW) == 0) {
        goto Bail;
    }
    
    /* check for command markers */
    ncomps = info->interest_comps->n;
    if (((marker_comp = ncomps - 2) >= 0) &&
        0 == r_util_name_comp_compare(info->interest_ndnb, info->interest_comps, marker_comp, NAME_BE, strlen(NAME_BE))) {
        if (NDNSHOULDLOG(ndnr, LM_8, NDNL_FINER))
            ndnr_debug_ndnb(ndnr, __LINE__, "name_enumeration", NULL,
                            info->interest_ndnb, info->pi->offset[NDN_PI_E]);
        res = r_proto_begin_enumeration(selfp, kind, info, marker_comp);
        goto Finish;
    } else if (((marker_comp = ncomps - 3) >= 0) &&
               0 == r_util_name_comp_compare(info->interest_ndnb, info->interest_comps, marker_comp, NAME_BE, strlen(NAME_BE)) &&
               0 == r_util_name_comp_compare(info->interest_ndnb, info->interest_comps, marker_comp + 1, ndnr->ndnr_keyid->buf, ndnr->ndnr_keyid->length)) {
        if (NDNSHOULDLOG(ndnr, LM_8, NDNL_FINER))
            ndnr_debug_ndnb(ndnr, __LINE__, "name_enumeration_repoid", NULL,
                            info->interest_ndnb, info->pi->offset[NDN_PI_E]);
        res = r_proto_begin_enumeration(selfp, kind, info, marker_comp);
        goto Finish;
    } else if (((marker_comp = ncomps - 5) >= 0) &&
               0 == r_util_name_comp_compare(info->interest_ndnb, info->interest_comps, marker_comp, NAME_BE, strlen(NAME_BE)) &&
               0 == r_util_name_comp_compare(info->interest_ndnb, info->interest_comps, marker_comp + 1, ndnr->ndnr_keyid->buf, ndnr->ndnr_keyid->length)) {
        if (NDNSHOULDLOG(ndnr, LM_8, NDNL_FINER))
            ndnr_debug_ndnb(ndnr, __LINE__, "name_enumeration_continuation",
                            NULL, info->interest_ndnb, info->pi->offset[NDN_PI_E]);
        res = r_proto_continue_enumeration(selfp, kind, info, marker_comp);
        goto Finish;
    } else if (((marker_comp = ncomps - 3) > 0) &&
               0 == r_util_name_comp_compare(info->interest_ndnb, info->interest_comps, marker_comp, REPO_SW, strlen(REPO_SW))) {
        if (NDNSHOULDLOG(ndnr, LM_8, NDNL_FINER))
            ndnr_debug_ndnb(ndnr, __LINE__, "repo_start_write", NULL,
                            info->interest_ndnb, info->pi->offset[NDN_PI_E]);
        res = r_proto_start_write(selfp, kind, info, marker_comp);
        goto Finish;
    } else if (((marker_comp = ncomps - 5) > 0) &&
               0 == r_util_name_comp_compare(info->interest_ndnb, info->interest_comps, marker_comp, REPO_SWC, strlen(REPO_SWC))) {
        if (NDNSHOULDLOG(ndnr, LM_8, NDNL_FINER))
            ndnr_debug_ndnb(ndnr, __LINE__, "repo_start_write_checked",
                            NULL, info->interest_ndnb, info->pi->offset[NDN_PI_E]);
        res = r_proto_start_write_checked(selfp, kind, info, marker_comp);
        goto Finish;
    } else if (((marker_comp = 0) == 0) &&
               name_comp_equal_prefix(info->interest_ndnb, info->interest_comps, marker_comp, REPO_AF, strlen(REPO_AF))) {
        if (NDNSHOULDLOG(ndnr, LM_8, NDNL_FINER))
            ndnr_debug_ndnb(ndnr, __LINE__, "repo_bulk_import",
                            NULL, info->interest_ndnb, info->pi->offset[NDN_PI_E]);
        res = r_proto_bulk_import(selfp, kind, info, marker_comp);
        goto Finish;
    }
    goto Bail;
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

// XXX these should probably be rationalized and added to ndn_name_util.c
/**
 * Compare a name component at index i to bytes in buf and return 1
 * if they are equal in the first length bytes.  The name component
 * must contain at least length bytes for this comparison to return
 * equality.
 * @returns 1 for equality, 0 for inequality.
 */
static int
name_comp_equal_prefix(const unsigned char *data,
                   const struct ndn_indexbuf *indexbuf,
                   unsigned int i, const void *buf, size_t length)
{
    const unsigned char *comp_ptr;
    size_t comp_size;
    
    if (ndn_name_comp_get(data, indexbuf, i, &comp_ptr, &comp_size) != 0)
        return(0);
    if (comp_size < length || memcmp(comp_ptr, buf, length) != 0)
        return(0);
    return(1);
}

PUBLIC void
r_proto_uri_listen(struct ndnr_handle *ndnr, struct ndn *ndn, const char *uri,
                   ndn_handler p, intptr_t intdata)
{
    struct ndn_charbuf *name;
    struct ndn_closure *closure = NULL;
    
    name = ndn_charbuf_create();
    ndn_name_from_uri(name, uri);
    if (p != NULL) {
        closure = calloc(1, sizeof(*closure));
        closure->p = p;
        closure->data = ndnr;
        closure->intdata = intdata;
    }
    ndn_set_interest_filter(ndn, name, closure);
    ndn_charbuf_destroy(&name);
}

// XXX - need an r_proto_uninit to uninstall the policy
PUBLIC void
r_proto_init(struct ndnr_handle *ndnr) {
    // nothing to do
}
/**
 * Install the listener for the namespaces that the parsed policy says to serve
 * 
 * Normal usage is to deactivate the old policy and then activate the new one
 */
PUBLIC void
r_proto_activate_policy(struct ndnr_handle *ndnr, struct ndnr_parsed_policy *pp) {
    int i;
    
    for (i = 0; i < pp->namespaces->n; i++) {
        if (NDNSHOULDLOG(ndnr, sdfdf, NDNL_INFO))
            ndnr_msg(ndnr, "Adding listener for policy namespace %s",
                     (char *)pp->store->buf + pp->namespaces->buf[i]);
        r_proto_uri_listen(ndnr, ndnr->direct_client,
                           (char *)pp->store->buf + pp->namespaces->buf[i],
                           r_proto_answer_req, 0);
    }
    if (NDNSHOULDLOG(ndnr, sdfdf, NDNL_INFO))
        ndnr_msg(ndnr, "Adding listener for policy global prefix %s",
                 (char *)pp->store->buf + pp->global_prefix_offset);
    r_proto_uri_listen(ndnr, ndnr->direct_client,
                       (char *)pp->store->buf + pp->global_prefix_offset,
                       r_proto_answer_req, 0);    
}
/**
 * Uninstall the listener for the namespaces that the parsed policy says to serve
 */
PUBLIC void
r_proto_deactivate_policy(struct ndnr_handle *ndnr, struct ndnr_parsed_policy *pp) {
    int i;

    if (NDNSHOULDLOG(ndnr, sdfdf, NDNL_INFO))
        ndnr_msg(ndnr, "Removing listener for policy global prefix %s",
                 (char *)pp->store->buf + pp->global_prefix_offset);
    r_proto_uri_listen(ndnr, ndnr->direct_client,
                       (char *)pp->store->buf + pp->global_prefix_offset,
                       NULL, 0);    
    for (i = 0; i < pp->namespaces->n; i++) {
        if (NDNSHOULDLOG(ndnr, sdfdf, NDNL_INFO))
            ndnr_msg(ndnr, "Removing listener for policy namespace %s",
                     (char *)pp->store->buf + pp->namespaces->buf[i]);
        r_proto_uri_listen(ndnr, ndnr->direct_client,
                           (char *)pp->store->buf + pp->namespaces->buf[i],
                           NULL, 0);
    }
    
}


/**
 * Construct a charbuf with an encoding of a RepositoryInfo
 */ 
PUBLIC int
r_proto_append_repo_info(struct ndnr_handle *ndnr,
                         struct ndn_charbuf *rinfo,
                         struct ndn_charbuf *names,
                         const char *info) {
    int res;
    struct ndn_charbuf *name = ndn_charbuf_create();
    if (name == NULL) return (-1);
    res = ndnb_element_begin(rinfo, NDN_DTAG_RepositoryInfo);
    res |= ndnb_tagged_putf(rinfo, NDN_DTAG_Version, "%s", "1.1");
    res |= ndnb_tagged_putf(rinfo, NDN_DTAG_Type, "%s", (names != NULL) ? "DATA" : "INFO");
    res |= ndnb_tagged_putf(rinfo, NDN_DTAG_RepositoryVersion, "%s", "2.0");
    res |= ndnb_element_begin(rinfo, NDN_DTAG_GlobalPrefixName); // same structure as Name
    res |= ndnb_element_end(rinfo);
    ndn_name_init(name);
    res |= ndn_name_from_uri(name, (char *)ndnr->parsed_policy->store->buf + ndnr->parsed_policy->global_prefix_offset);
    res |= ndn_name_append_components(rinfo, name->buf, 1, name->length - 1);
    res |= ndnb_tagged_putf(rinfo, NDN_DTAG_LocalName, "%s", "Repository");
    if (names != NULL)
        res |= ndn_charbuf_append_charbuf(rinfo, names);
    if (info != NULL)
        res |= ndnb_tagged_putf(rinfo, NDN_DTAG_InfoString, "%s", info);
    // There is an optional NDN_DTAG_InfoString in the encoding here, like the LocalName
    res |= ndnb_element_end(rinfo); // NDN_DTAG_RepositoryInfo
    ndn_charbuf_destroy(&name);
    return (res);
}

static struct ndn_charbuf *
r_proto_mktemplate(struct ndnr_expect_content *md, struct ndn_upcall_info *info)
{
    struct ndn_charbuf *templ = ndn_charbuf_create();
    ndnb_element_begin(templ, NDN_DTAG_Interest); // same structure as Name
    ndnb_element_begin(templ, NDN_DTAG_Name);
    ndnb_element_end(templ); /* </Name> */
    // XXX - use pubid if possible
    // XXX - if start-write was scoped, use scope here?
    ndnb_tagged_putf(templ, NDN_DTAG_MinSuffixComponents, "%d", 1);
    ndnb_tagged_putf(templ, NDN_DTAG_MaxSuffixComponents, "%d", 1);
    ndnb_element_end(templ); /* </Interest> */
    return(templ);
}

PUBLIC enum ndn_upcall_res
r_proto_expect_content(struct ndn_closure *selfp,
                 enum ndn_upcall_kind kind,
                 struct ndn_upcall_info *info)
{
    struct ndn_charbuf *name = NULL;
    struct ndn_charbuf *templ = NULL;
    const unsigned char *ndnb = NULL;
    size_t ndnb_size = 0;
    const unsigned char *ib = NULL; /* info->interest_ndnb */
    struct ndn_indexbuf *ic = NULL;
    int res;
    struct ndnr_expect_content *md = selfp->data;
    struct ndnr_handle *ndnr = NULL;
    struct content_entry *content = NULL;
    int i;
    int empty_slots;
    intmax_t segment;

    if (kind == NDN_UPCALL_FINAL) {
        if (md != NULL) {
            selfp->data = NULL;
            free(md);
            md = NULL;
        }
        free(selfp);
        return(NDN_UPCALL_RESULT_OK);
    }
    if (md == NULL) {
        return(NDN_UPCALL_RESULT_ERR);
    }
    if (md->done)
        return(NDN_UPCALL_RESULT_ERR);
    ndnr = (struct ndnr_handle *)md->ndnr;
    if (kind == NDN_UPCALL_INTEREST_TIMED_OUT) {
        if (md->tries > NDNR_MAX_RETRY) {
            ndnr_debug_ndnb(ndnr, __LINE__, "fetch_failed", NULL,
                            info->interest_ndnb, info->pi->offset[NDN_PI_E]);
            return(NDN_UPCALL_RESULT_ERR);
        }
        md->tries++;
        return(NDN_UPCALL_RESULT_REEXPRESS);
    }
    if (kind == NDN_UPCALL_CONTENT_UNVERIFIED) {
        // XXX - Some forms of key locator can confuse libndn. Don't provoke it to fetch keys until that is hardened.
        if (NDNSHOULDLOG(ndnr, sdfdf, NDNL_FINE))
            ndnr_debug_ndnb(ndnr, __LINE__, "key_needed", NULL, info->content_ndnb, info->pco->offset[NDN_PCO_E]);
    }
    switch (kind) {
        case NDN_UPCALL_CONTENT:
        case NDN_UPCALL_CONTENT_UNVERIFIED:
#if (NDN_API_VERSION >= 4004)
        case NDN_UPCALL_CONTENT_RAW:
        case NDN_UPCALL_CONTENT_KEYMISSING:
#endif
            break;
        default:
            return(NDN_UPCALL_RESULT_ERR);
    }
    
    ndnb = info->content_ndnb;
    ndnb_size = info->pco->offset[NDN_PCO_E];
    ib = info->interest_ndnb;
    ic = info->interest_comps;
    
    content = process_incoming_content(ndnr, r_io_fdholder_from_fd(ndnr, ndn_get_connection_fd(info->h)),
                                       (void *)ndnb, ndnb_size, NULL);
    if (content == NULL) {
        ndnr_msg(ndnr, "r_proto_expect_content: failed to process incoming content");
        return(NDN_UPCALL_RESULT_ERR);
    }
    r_store_commit_content(ndnr, content);
    r_proto_initiate_key_fetch(ndnr, ndnb, info->pco, 0,
                               r_store_content_cookie(ndnr, content));
    
    md->tries = 0;
    segment = r_util_segment_from_component(ib, ic->buf[ic->n - 2], ic->buf[ic->n - 1]);

    if (ndn_is_final_block(info) == 1)
        md->final = segment;
    
    if (md->keyfetch != 0 && segment <= 0) {
        /* This should either be a key, or a link to get to it. */
        if (info->pco->type == NDN_CONTENT_LINK) {
            r_proto_initiate_key_fetch(ndnr, ndnb, info->pco, 1, md->keyfetch);
        }
        else if (info->pco->type == NDN_CONTENT_KEY) {
            if (NDNSHOULDLOG(ndnr, sdfdf, NDNL_FINE))
                ndnr_msg(ndnr, "key_arrived %u", (unsigned)(md->keyfetch));
            // XXX - should check that we got the right key.
        }
        else {
            // not a key or a link.  Log it so we have a clue.
            ndnr_msg(ndnr, "ERROR - got something else when trying to fetch key for item %u", (unsigned)(md->keyfetch));
        }
    }
    
    // Unsegmented content should skip pipeline processing.
    if (segment < 0) {
        if (md->expect_complete != NULL) {
            (md->expect_complete)(selfp, kind, info);
        }
        return(NDN_UPCALL_RESULT_OK);
    }
    
    /* retire the current segment and any segments beyond the final one */
    empty_slots = 0;
    for (i = 0; i < NDNR_PIPELINE; i++) {
        if (md->outstanding[i] == segment || ((md->final > -1) && (md->outstanding[i] > md->final)))
            md->outstanding[i] = -1;
        if (md->outstanding[i] == -1)
            empty_slots++;
    
    }
    md->done = (md->final > -1) && (empty_slots == NDNR_PIPELINE);
    // if there is a completion handler set up, and we've got all the blocks
    // call it -- note that this may not be the last block if they arrive out of order.
    if (md->done && (md->expect_complete != NULL))
        (md->expect_complete)(selfp, kind, info);
                              
    if (md->final > -1) {
        return (NDN_UPCALL_RESULT_OK);
    }

    name = ndn_charbuf_create();
    if (ic->n < 2) abort();    
    templ = r_proto_mktemplate(md, info);
    /* fill the pipeline with new requests */
    for (i = 0; i < NDNR_PIPELINE; i++) {
        if (md->outstanding[i] == -1) {
            ndn_name_init(name);
            res = ndn_name_append_components(name, ib, ic->buf[0], ic->buf[ic->n - 2]);
            if (res < 0) abort();
            ndn_name_append_numeric(name, NDN_MARKER_SEQNUM, ++(selfp->intdata));
            res = ndn_express_interest(info->h, name, selfp, templ);
            if (res < 0) abort();
            md->outstanding[i] = selfp->intdata;
        }
    }
    ndn_charbuf_destroy(&templ);
    ndn_charbuf_destroy(&name);
    
    return(NDN_UPCALL_RESULT_OK);
}

static int
r_proto_policy_update(struct ndn_schedule *sched,
                      void *clienth,
                      struct ndn_scheduled_event *ev,
                      int flags)
{
    struct ndnr_handle *ndnr = clienth;
    struct ndn_charbuf *name = ev->evdata;
    struct content_entry *content = NULL;
    const unsigned char *content_msg = NULL;
    const unsigned char *vers = NULL;
    size_t vers_size = 0;
    struct ndn_parsed_ContentObject pco = {0};
    struct ndn_indexbuf *nc;
    struct ndn_charbuf *policy = NULL;
    struct ndn_charbuf *policy_link_cob = NULL;
    struct ndn_charbuf *policyFileName = NULL;
    const unsigned char *buf = NULL;
    size_t length = 0;
    struct ndnr_parsed_policy *pp;
    int segment = -1;
    int final = 0;
    int res;
    int ans = -1;
    int fd = -1;
    
    if ((flags & NDN_SCHEDULE_CANCEL) != 0) {
        ans = 0;
        goto Bail;
    }
    
    policy = ndn_charbuf_create();
    nc = ndn_indexbuf_create();
    do {
        ndn_name_append_numeric(name, NDN_MARKER_SEQNUM, ++segment);
        content = r_store_lookup_ndnb(ndnr, name->buf, name->length);
        if (content == NULL) {
            ndnr_debug_ndnb(ndnr, __LINE__, "policy lookup failed for", NULL,
                            name->buf, name->length);
            goto Bail;
        }
        ndn_name_chop(name, NULL, -1);
        content_msg = r_store_content_base(ndnr, content);
        if (content_msg == NULL) {
            ndnr_debug_ndnb(ndnr, __LINE__, "Policy read failed for", NULL,
                            name->buf, name->length);
            goto Bail;            
        }
        res = ndn_parse_ContentObject(content_msg, r_store_content_size(ndnr, content), &pco, nc);
        res = ndn_ref_tagged_BLOB(NDN_DTAG_Content, content_msg,
                                  pco.offset[NDN_PCO_B_Content],
                                  pco.offset[NDN_PCO_E_Content],
                                  &buf, &length);
        ndn_charbuf_append(policy, buf, length);
        final = ndn_is_final_pco(content_msg, &pco, nc);
    } while (!final);
    
    pp = ndnr_parsed_policy_create();
    if (pp == NULL) {
        ndnr_msg(ndnr, "Parsed policy allocation error");
        goto Bail;
    }
    memmove(pp->version, vers, vers_size);
    if (r_proto_parse_policy(ndnr, policy->buf, policy->length, pp) < 0) {
        ndnr_msg(ndnr, "Malformed policy");
        goto Bail;
    }
    res = strcmp((char *)pp->store->buf + pp->global_prefix_offset,
                 (char *)ndnr->parsed_policy->store->buf + ndnr->parsed_policy->global_prefix_offset);
    if (0 != res) {
        ndnr_msg(ndnr, "Policy global prefix mismatch");
        goto Bail;
    }
    policy_link_cob = ndnr_init_policy_link_cob(ndnr, ndnr->direct_client, name);
    if (policy_link_cob != NULL) {
        ndn_charbuf_destroy(&ndnr->policy_link_cob);
        ndnr->policy_link_cob = policy_link_cob;
    }
    policyFileName = ndn_charbuf_create();
    ndn_charbuf_putf(policyFileName, "%s/repoPolicy", ndnr->directory);
    fd = open(ndn_charbuf_as_string(policyFileName), O_WRONLY | O_CREAT, 0666);
    if (fd < 0) {
        ndnr_msg(ndnr, "open policy: %s (errno = %d)", strerror(errno), errno);
        goto Bail;
    }
    lseek(fd, 0, SEEK_SET);
    res = write(fd, ndnr->policy_link_cob->buf, ndnr->policy_link_cob->length);
    if (res == -1) {
        ndnr_msg(ndnr, "write policy: %s (errno = %d)", strerror(errno), errno);
        goto Bail;
    }
    res = ftruncate(fd, ndnr->policy_link_cob->length);
    if (res == -1) {
        ndnr_msg(ndnr, "Policy truncate %u :%s (errno = %d)",
                 fd, strerror(errno), errno);
        goto Bail;
    }
    close(fd);
    fd = -1;
    r_proto_deactivate_policy(ndnr, ndnr->parsed_policy);
    ndnr_parsed_policy_destroy(&ndnr->parsed_policy);
    ndnr->parsed_policy = pp;
    r_proto_activate_policy(ndnr, pp);
    
    ans = 0;
    
Bail:
    ndn_charbuf_destroy(&name);
    ndn_indexbuf_destroy(&nc);
    ndn_charbuf_destroy(&policy);
    ndn_charbuf_destroy(&policyFileName);
    if (fd >= 0) close(fd);
    return (ans);
    
}    

static enum ndn_upcall_res
r_proto_policy_complete(struct ndn_closure *selfp,
                        enum ndn_upcall_kind kind,
                        struct ndn_upcall_info *info)
{
    struct ndnr_expect_content *md = selfp->data;
    struct ndnr_handle *ndnr = (struct ndnr_handle *)md->ndnr;
    const unsigned char *ndnb;
    size_t ndnb_size;
    const unsigned char *vers = NULL;
    size_t vers_size = 0;
    struct ndn_indexbuf *cc;
    struct ndn_charbuf *name;
    
    // the version of the new policy must be greater than the exist one
    // or we will not activate it and update the link to point to it.
    
    ndnb = info->content_ndnb;
    ndnb_size = info->pco->offset[NDN_PCO_E];
    cc = info->content_comps;
    ndn_name_comp_get(ndnb, cc, cc->n - 3, &vers, &vers_size);
    if (vers_size != 7 || vers[0] != NDN_MARKER_VERSION)
        return(NDN_UPCALL_RESULT_ERR);
    if (memcmp(vers, ndnr->parsed_policy->version, sizeof(ndnr->parsed_policy->version)) <= 0) {
        if (NDNSHOULDLOG(ndnr, LM_128, NDNL_INFO))
            ndnr_debug_ndnb(ndnr, __LINE__, "r_proto_policy_complete older policy ignored", NULL,
                            ndnb, ndnb_size);        
        return (NDN_UPCALL_RESULT_ERR);
    }
    // all components not including segment
    name = ndn_charbuf_create();
    if (name == NULL || ndn_name_init(name) < 0) {
        ndnr_msg(ndnr,"r_proto_policy_complete no memory to update policy");
        ndn_charbuf_destroy(&name);
        return (NDN_UPCALL_RESULT_ERR);
    }
    ndn_name_append_components(name, ndnb, cc->buf[0], cc->buf[cc->n - 2]);
    ndn_schedule_event(ndnr->sched, 500, r_proto_policy_update, name, 0);
    if (NDNSHOULDLOG(ndnr, LM_128, NDNL_FINEST))
        ndnr_msg(ndnr,"r_proto_policy_complete update scheduled");        
    
    return (NDN_UPCALL_RESULT_OK);
}

static enum ndn_upcall_res
r_proto_start_write(struct ndn_closure *selfp,
                    enum ndn_upcall_kind kind,
                    struct ndn_upcall_info *info,
                    int marker_comp)
{
    struct ndnr_handle *ndnr = NULL;
    struct ndn_charbuf *templ = NULL;
    struct ndn_closure *incoming = NULL;
    struct ndnr_expect_content *expect_content = NULL;
    struct ndn_charbuf *reply_body = NULL;
    struct ndn_charbuf *name = NULL;
    struct ndn_indexbuf *ic = NULL;
    enum ndn_upcall_res ans = NDN_UPCALL_RESULT_ERR;
    struct ndn_charbuf *msg = NULL;
    int res = 0;
    int start = 0;
    int end = 0;
    int is_policy = 0;
    int i;
    struct ndn_signing_params sp = NDN_SIGNING_PARAMS_INIT;
    
    // XXX - Check for valid nonce
    // XXX - Check for pubid - if present and not ours, do not respond.
    // Check for answer origin kind.
    // If Exclude is there, there might be something fishy going on.
    
    ndnr = (struct ndnr_handle *)selfp->data;
    if (ndnr->start_write_scope_limit < 3) {
        start = info->pi->offset[NDN_PI_B_Scope];
        end = info->pi->offset[NDN_PI_E_Scope];
        if (start == end || info->pi->scope > ndnr->start_write_scope_limit) {
            if (NDNSHOULDLOG(ndnr, LM_128, NDNL_INFO))
                ndnr_msg(ndnr, "r_proto_start_write: interest scope exceeds limit");
            return(NDN_UPCALL_RESULT_OK);
        }
    }
    // don't handle the policy file here
    start = info->pi->offset[NDN_PI_B_Name];
    end = info->interest_comps->buf[marker_comp - 1]; // not including version or marker
    name = ndn_charbuf_create();
    ndn_charbuf_append(name, info->interest_ndnb + start, end - start);
    ndn_charbuf_append_closer(name);
    if (0 ==ndn_compare_names(name->buf, name->length,
                              ndnr->policy_name->buf, ndnr->policy_name->length))
        is_policy = 1;
    
    /* Generate our reply */
    start = info->pi->offset[NDN_PI_B_Name];
    end = info->interest_comps->buf[info->pi->prefix_comps];
    name->length = 0;
    ndn_charbuf_append(name, info->interest_ndnb + start, end - start);
    ndn_charbuf_append_closer(name);
    msg = ndn_charbuf_create();
    reply_body = ndn_charbuf_create();
    r_proto_append_repo_info(ndnr, reply_body, NULL, NULL);
    sp.freshness = 12; /* seconds */
    res = ndn_sign_content(info->h, msg, name, &sp,
                           reply_body->buf, reply_body->length);
    if (res < 0)
        goto Bail;
    if (NDNSHOULDLOG(ndnr, LM_128, NDNL_FINE))
        ndnr_debug_ndnb(ndnr, __LINE__, "r_proto_start_write response", NULL,
                        msg->buf, msg->length);
    res = ndn_put(info->h, msg->buf, msg->length);
    if (res < 0) {
        ndnr_debug_ndnb(ndnr, __LINE__, "r_proto_start_write ndn_put FAILED", NULL,
                        msg->buf, msg->length);
        goto Bail;
    }

    /* Send an interest for segment 0 */
    expect_content = calloc(1, sizeof(*expect_content));
    if (expect_content == NULL)
        goto Bail;
    expect_content->ndnr = ndnr;
    expect_content->final = -1;
    for (i = 0; i < NDNR_PIPELINE; i++)
        expect_content->outstanding[i] = -1;
    if (is_policy) {
        expect_content->expect_complete = &r_proto_policy_complete;
        if (NDNSHOULDLOG(ndnr, LM_128, NDNL_FINE))
            ndnr_msg(ndnr, "r_proto_start_write: is policy file");
    }
    incoming = calloc(1, sizeof(*incoming));
    if (incoming == NULL)
        goto Bail;
    incoming->p = &r_proto_expect_content;
    incoming->data = expect_content;
    templ = r_proto_mktemplate(expect_content, NULL);
    ic = info->interest_comps;
    ndn_name_init(name);
    ndn_name_append_components(name, info->interest_ndnb, ic->buf[0], ic->buf[marker_comp]);
    ndn_name_append_numeric(name, NDN_MARKER_SEQNUM, 0);
    expect_content->outstanding[0] = 0;
    res = ndn_express_interest(info->h, name, incoming, templ);
    if (res >= 0) {
        /* upcall will free these when it is done. */
        incoming = NULL;
        expect_content = NULL;
        ans = NDN_UPCALL_RESULT_INTEREST_CONSUMED;
    }
    else {
        ndnr_debug_ndnb(ndnr, __LINE__, "r_proto_start_write ndn_express_interest FAILED", NULL,
                        name->buf, name->length);
        goto Bail;
    }
    
Bail:
    if (incoming != NULL)
        free(incoming);
    if (expect_content != NULL)
        free(expect_content);
    ndn_charbuf_destroy(&templ);
    ndn_charbuf_destroy(&name);
    ndn_charbuf_destroy(&reply_body);
    ndn_charbuf_destroy(&msg);
    return(ans);
}

static enum ndn_upcall_res
r_proto_start_write_checked(struct ndn_closure *selfp,
                            enum ndn_upcall_kind kind,
                            struct ndn_upcall_info *info,
                            int marker_comp)
{
    struct ndnr_handle *ndnr = NULL;
    enum ndn_upcall_res ans = NDN_UPCALL_RESULT_OK;
    struct ndn_indexbuf *ic = NULL;
    struct content_entry *content = NULL;
    struct ndn_parsed_interest parsed_interest = {0};
    struct ndn_parsed_interest *pi = &parsed_interest;
    struct ndn_charbuf *name = NULL;
    struct ndn_charbuf *interest = NULL;
    struct ndn_indexbuf *comps = NULL;
    struct ndn_charbuf *msg = NULL;
    struct ndn_charbuf *reply_body = NULL;
    int start = 0;
    int end = 0;
    struct ndn_signing_params sp = NDN_SIGNING_PARAMS_INIT;
    int res = 0;
    
    // XXX - do we need to disallow the policy file here too?
    ndnr = (struct ndnr_handle *)selfp->data;
    if (ndnr->start_write_scope_limit < 3) {
        start = info->pi->offset[NDN_PI_B_Scope];
        end = info->pi->offset[NDN_PI_E_Scope];
        if (start == end || info->pi->scope > ndnr->start_write_scope_limit) {
            if (NDNSHOULDLOG(ndnr, LM_128, NDNL_INFO))
                ndnr_msg(ndnr, "r_proto_start_write_checked: interest scope exceeds limit");
            return(NDN_UPCALL_RESULT_OK);
        }
    }
    name = ndn_charbuf_create();
    ndn_name_init(name);
    ic = info->interest_comps;
    ndn_name_append_components(name, info->interest_ndnb, ic->buf[0], ic->buf[marker_comp]);
    ndn_name_append_components(name, info->interest_ndnb, ic->buf[marker_comp + 2], ic->buf[ic->n - 1]);
    // Make an interest for the exact item we're checking
    interest = ndn_charbuf_create();
    ndnb_element_begin(interest, NDN_DTAG_Interest);
    ndn_charbuf_append_charbuf(interest, name);
    ndnb_element_end(interest); /* </Interest> */
    // Parse it
    comps = ndn_indexbuf_create();
    res = ndn_parse_interest(interest->buf, interest->length, pi, comps);
    if (res < 0)
        abort();
    if (NDNSHOULDLOG(ndnr, LM_128, NDNL_FINE))
        ndnr_debug_ndnb(ndnr, __LINE__, "r_proto_start_write_checked looking for", NULL,
                        interest->buf, interest->length);
    content = r_store_lookup(ndnr, interest->buf, pi, comps);
    ndn_charbuf_destroy(&interest);
    ndn_indexbuf_destroy(&comps);
    if (content == NULL) {
        ndn_charbuf_destroy(&name);
        if (NDNSHOULDLOG(ndnr, LM_128, NDNL_FINE))
            ndnr_msg(ndnr, "r_proto_start_write_checked: NOT PRESENT");
        // XXX - dropping into the start_write case means we do not check the provided digest when fetching, so this is not completely right.
        return(r_proto_start_write(selfp, kind, info, marker_comp));
    }
    // what's the return value if the item is in the repository already?
    // if it does have it -- getRepoInfo(interest.name(), null, target_names)
    // response has local name as the full name of the thing we claim to have --
    // take the command marker and nonce out of the middle of the incoming interest,
    // which is what we have in the "name" of the interest we created to check the content.
    ///// begin copied code
    /* Generate our reply */
    msg = ndn_charbuf_create();
    reply_body = ndn_charbuf_create();
    r_proto_append_repo_info(ndnr, reply_body, name, NULL);
    start = info->pi->offset[NDN_PI_B_Name];
    end = info->interest_comps->buf[info->pi->prefix_comps];
    name->length = 0;
    ndn_charbuf_append(name, info->interest_ndnb + start, end - start);
    ndn_charbuf_append_closer(name);
    sp.freshness = 12; /* Seconds */
    res = ndn_sign_content(info->h, msg, name, &sp,
                           reply_body->buf, reply_body->length);
    if (res < 0)
        goto Bail;
    if (NDNSHOULDLOG(ndnr, LM_128, NDNL_FINE))
        ndnr_msg(ndnr, "r_proto_start_write_checked PRESENT");
    res = ndn_put(info->h, msg->buf, msg->length);
    if (res < 0) {
        // note the error somehow.
        ndnr_debug_ndnb(ndnr, __LINE__, "r_proto_start_write_checked ndn_put FAILED", NULL,
                        msg->buf, msg->length);
    }
    //// end of copied code
Bail:
    ndn_charbuf_destroy(&name);
    ndn_charbuf_destroy(&reply_body);
    ndn_charbuf_destroy(&msg);
    return(ans);
}

/**
 * Returns 1 if the Exclude in the interest described by the info parameter
 * would exclude the full name in name.
 */
static int
r_proto_check_exclude(struct ndnr_handle *ndnr,
                      struct ndn_upcall_info *info,
                      struct ndn_charbuf *name)
{
    struct ndn_buf_decoder decoder;
    struct ndn_buf_decoder *d = NULL;
    const unsigned char *comp = NULL;
    size_t comp_size;
    size_t name_comp_size;
    struct ndn_indexbuf *name_comps = NULL;
    const unsigned char *name_string = NULL;
    int ci;
    int res;
    int ans = 0;
    
    if (info->pi->offset[NDN_PI_B_Exclude] < info->pi->offset[NDN_PI_E_Exclude]) {
        d = ndn_buf_decoder_start(&decoder,
                                  info->interest_ndnb + info->pi->offset[NDN_PI_B_Exclude],
                                  info->pi->offset[NDN_PI_E_Exclude] -
                                  info->pi->offset[NDN_PI_B_Exclude]);
        
        // handle easy case of <Exclude><Component>...</Exclude>
        // XXX - this may need to be better, but not necessarily complete
        if (ndn_buf_match_dtag(d, NDN_DTAG_Exclude)) {
            ndn_buf_advance(d);
        } else 
            goto Bail;
        // there may be something to check, so get the components of the name
        name_comps = ndn_indexbuf_create();
        if (ndn_name_split(name, name_comps) < 0)
            goto Bail;
        // the component in the name we are matching is last plus one of the interest
        // but ci includes an extra value for the end of the last component
        ci = info->interest_comps->n;
        res = ndn_name_comp_get(name->buf, name_comps, ci - 1, &name_string, &name_comp_size);
        if (res < 0)
            goto Bail;
        while (ndn_buf_match_dtag(d, NDN_DTAG_Component)) {
            ndn_buf_advance(d);
            comp_size = 0;
            if (ndn_buf_match_blob(d, &comp, &comp_size))
                ndn_buf_advance(d);
            ndn_buf_check_close(d);
            if (comp_size == name_comp_size) {
                res = memcmp(comp, name_string, comp_size);
                if (res == 0) {
                    ans = 1;
                    goto Bail; /* One of the explicit excludes */
                }
                if (res > 0)
                    break;
            }
        }
    }
    
Bail:
    ndn_indexbuf_destroy(&name_comps);
    if (NDNSHOULDLOG(ndnr, LM_8, NDNL_FINE))
        ndnr_msg(ndnr, "r_proto_check_exclude: do%s exclude", (ans == 1) ? "" : " not");
    return(ans);
}

void
r_proto_finalize_enum_state(struct hashtb_enumerator *e)
{
    struct enum_state *es = e->data;
    unsigned i;
    
    ndn_charbuf_destroy(&es->name);
    ndn_charbuf_destroy(&es->interest); // unnecessary?
    ndn_charbuf_destroy(&es->reply_body);
    ndn_indexbuf_destroy(&es->interest_comps);
    for (i = 0; i < ENUM_N_COBS; i++)
        ndn_charbuf_destroy(&(es->cob[i]));
    return;
}

#define ENUMERATION_STATE_TICK_MICROSEC 1000000
/**
 * Remove expired enumeration table entries
 */
static int
reap_enumerations(struct ndn_schedule *sched,
                  void *clienth,
                  struct ndn_scheduled_event *ev,
                  int flags)
{
    struct ndnr_handle *ndnr = clienth;
    struct hashtb_enumerator ee;
    struct hashtb_enumerator *e = &ee;
    struct enum_state *es = NULL;
    
    if ((flags & NDN_SCHEDULE_CANCEL) != 0) {
        ndnr->reap_enumerations = NULL;
        return(0);
    }
    hashtb_start(ndnr->enum_state_tab, e);
    for (es = e->data; es != NULL; es = e->data) {
        if (es->active != ES_ACTIVE &&
            r_util_timecmp(es->lastuse_sec + es->lifetime, es->lastuse_usec,
                           ndnr->sec, ndnr->usec) <= 0) {
                if (NDNSHOULDLOG(ndnr, LM_8, NDNL_FINER))
                    ndnr_debug_ndnb(ndnr, __LINE__, "reap enumeration state", NULL,
                                    es->name->buf, es->name->length);            		// remove the entry from the hash table, finalization frees data
                hashtb_delete(e);
            }
        hashtb_next(e);
    }
    hashtb_end(e);
    if (hashtb_n(ndnr->enum_state_tab) == 0) {
        ndnr->reap_enumerations = NULL;
        return(0);
    }
    return(ENUMERATION_STATE_TICK_MICROSEC);
}
static void
reap_enumerations_needed(struct ndnr_handle *ndnr)
{
    if (ndnr->reap_enumerations == NULL)
        ndnr->reap_enumerations = ndn_schedule_event(ndnr->sched,
                                                     ENUMERATION_STATE_TICK_MICROSEC,
                                                     reap_enumerations,
                                                     NULL, 0);
}

static enum ndn_upcall_res
r_proto_begin_enumeration(struct ndn_closure *selfp,
                          enum ndn_upcall_kind kind,
                          struct ndn_upcall_info *info,
                          int marker_comp)
{
    struct ndnr_handle *ndnr = NULL;
    enum ndn_upcall_res ans = NDN_UPCALL_RESULT_ERR;
    struct ndn_parsed_interest parsed_interest = {0};
    struct ndn_parsed_interest *pi = &parsed_interest;
    struct hashtb_enumerator enumerator = {0};
    struct hashtb_enumerator *e = &enumerator;
    struct ndn_charbuf *name = NULL;
    struct ndn_charbuf *cob = NULL;
    struct ndn_charbuf *interest = NULL;
    struct ndn_indexbuf *comps = NULL;
    int res;
    struct content_entry *content = NULL;
    struct enum_state *es = NULL;
    
    ndnr = (struct ndnr_handle *)selfp->data;
    // Construct a name up to but not including the begin enumeration marker component
    name = ndn_charbuf_create();
    ndn_name_init(name);
    ndn_name_append_components(name, info->interest_ndnb,
                               info->interest_comps->buf[0],
                               info->interest_comps->buf[marker_comp]);
    // Make an interest for the part of the namespace we are after, from the name
    interest = ndn_charbuf_create();
    ndnb_element_begin(interest, NDN_DTAG_Interest);
    ndn_charbuf_append_charbuf(interest, name);
    ndnb_element_end(interest); /* </Interest> */
    
    // Parse it
    comps = ndn_indexbuf_create();
    res = ndn_parse_interest(interest->buf, interest->length, pi, comps);
    if (res < 0)
        abort();
    // Look for a previous enumeration under this prefix
    hashtb_start(ndnr->enum_state_tab, e);
    res = hashtb_seek(e, name->buf, name->length, 0);
    es = e->data;
    if (NDNSHOULDLOG(ndnr, LM_8, NDNL_FINE))
        ndnr_debug_ndnb(ndnr, __LINE__, "enumeration: begin hash key", NULL,
                        name->buf, name->length);
    // Do not restart an active enumeration, it is probably a duplicate interest
    // TODO: may need attention when es->active == ES_ACTIVE_PENDING_INACTIVE
    if (res == HT_OLD_ENTRY && es->active != ES_INACTIVE) {
        if (es->next_segment > 0)
            cob = es->cob[(es->next_segment - 1) % ENUM_N_COBS];
        if (cob && ndn_content_matches_interest(cob->buf, cob->length, 1, NULL,
                                         info->interest_ndnb, info->pi->offset[NDN_PI_E], info->pi)) {
            if (NDNSHOULDLOG(ndnr, LM_8, NDNL_FINER))
                ndnr_msg(ndnr, "enumeration: duplicate request for last cob");
            ndn_put(info->h, cob->buf, cob->length);
            es->cob_deferred[(es->next_segment - 1) % ENUM_N_COBS] = 0;
            ans = NDN_UPCALL_RESULT_INTEREST_CONSUMED;
        } else {
            if (NDNSHOULDLOG(ndnr, LM_8, NDNL_FINEST)) {
                ndnr_msg(ndnr, "enumeration: restart of active enumeration, or excluded");
                ndnr_debug_ndnb(ndnr, __LINE__, "enum    interest: ", NULL, info->interest_ndnb, info->pi->offset[NDN_PI_E]);
                if (cob != NULL)
                    ndnr_debug_ndnb(ndnr, __LINE__, "enum cob content: ", NULL, cob->buf, cob->length);
            }
            ans = NDN_UPCALL_RESULT_OK;
        }
        hashtb_end(e);
        goto Bail;
    }
    // Continue to construct the name under which we will respond: %C1.E.be
    ndn_name_append_components(name, info->interest_ndnb,
                               info->interest_comps->buf[marker_comp],
                               info->interest_comps->buf[marker_comp + 1]);
    // Append the repository key id %C1.K.%00<repoid>
    ndn_name_append(name, ndnr->ndnr_keyid->buf, ndnr->ndnr_keyid->length);
    
    if (res == HT_NEW_ENTRY || es->starting_cookie != ndnr->cookie) {
        // this is a new enumeration, the time is now.
        res = ndn_create_version(info->h, name, NDN_V_NOW, 0, 0);
        if (es->name != NULL)
            ndn_charbuf_destroy(&es->name);
        es->name = ndn_charbuf_create();
        ndn_charbuf_append_charbuf(es->name, name);
        es->starting_cookie = ndnr->cookie; // XXX - a conservative indicator of change
    }
    ndn_charbuf_destroy(&name);
    // check the exclude against the result name
    if (NDNSHOULDLOG(ndnr, LM_8, NDNL_FINE))
        ndnr_debug_ndnb(ndnr, __LINE__, "begin enum: result name", NULL,
                        es->name->buf, es->name->length);
    
    if (r_proto_check_exclude(ndnr, info, es->name) > 0) {
        hashtb_end(e);
        goto Bail;
    }

    // do we have anything that matches this enumeration request?
    content = r_store_find_first_match_candidate(ndnr, interest->buf, pi);
    if (content != NULL &&
        !r_store_content_matches_interest_prefix(ndnr, content, interest->buf, interest->length))
        content = NULL;
    ndn_charbuf_destroy(&es->cob[0]);
    es->cob[0] = ndn_charbuf_create();
    memset(es->cob_deferred, 0, sizeof(es->cob_deferred));
    ndn_charbuf_destroy(&es->reply_body);
    es->reply_body = ndn_charbuf_create();
    ndnb_element_begin(es->reply_body, NDN_DTAG_Collection);
    es->content = content;
    ndn_charbuf_destroy(&es->interest);
    es->interest = interest;
    interest = NULL;
    ndn_indexbuf_destroy(&es->interest_comps);
    es->interest_comps = comps;
    comps = NULL;
    es->next_segment = 0;
    es->lastuse_sec = ndnr->sec;
    es->lastuse_usec = ndnr->usec;
    if (content) {
        es->lifetime = 3 * ndn_interest_lifetime_seconds(info->interest_ndnb, pi);
        es->active = ES_ACTIVE;
    } else {
        es->lifetime = ndn_interest_lifetime_seconds(info->interest_ndnb, pi);
        es->active = ES_PENDING;
    }
    hashtb_end(e);
    reap_enumerations_needed(ndnr);
    if (content)
        ans = r_proto_continue_enumeration(selfp, kind, info, marker_comp);
    else
        ans = NDN_UPCALL_RESULT_OK;
Bail:
    ndn_charbuf_destroy(&name);
    ndn_charbuf_destroy(&interest);
    ndn_indexbuf_destroy(&comps);
    return(ans);
}

static enum ndn_upcall_res
r_proto_continue_enumeration(struct ndn_closure *selfp,
                             enum ndn_upcall_kind kind,
                             struct ndn_upcall_info *info,
                             int marker_comp) {
    // XXX - watch out for pipelined interests for the enumerations -- there
    // MUST be an active enumeration continuation before we do anything here.
    // Should chop 1 component off interest -- which will look like
    // ndn:/.../%C1.E.be/%C1.M.K%00.../%FD.../%00%02
    struct ndn_charbuf *hashkey = NULL;
    struct ndn_charbuf *result_name = NULL;
    struct ndn_charbuf *cob = NULL;
    struct ndn_indexbuf *ic = NULL;
    intmax_t segment;
    struct enum_state *es = NULL;
    struct ndnr_handle *ndnr = NULL;
    struct hashtb_enumerator enumerator = {0};
    struct hashtb_enumerator *e = &enumerator;
    struct ndn_signing_params sp = NDN_SIGNING_PARAMS_INIT;
    int cobs_deferred;
    int i;
    int res = 0;
    
    ndnr = (struct ndnr_handle *)selfp->data;
    ic = info->interest_comps;
    hashkey=ndn_charbuf_create();
    ndn_name_init(hashkey);
    ndn_name_append_components(hashkey, info->interest_ndnb,
                               info->interest_comps->buf[0],
                               info->interest_comps->buf[marker_comp]);
    hashtb_start(ndnr->enum_state_tab, e);
    res = hashtb_seek(e, hashkey->buf, hashkey->length, 0);
    ndn_charbuf_destroy(&hashkey);
    if (res != HT_OLD_ENTRY) {
        hashtb_end(e);
        return(NDN_UPCALL_RESULT_ERR);
    }
    es = e->data;
    if (es->active != ES_ACTIVE && es->active != ES_ACTIVE_PENDING_INACTIVE) {
        hashtb_end(e);
        return(NDN_UPCALL_RESULT_ERR);
    }
    // If there is a segment in the request, get the value.
    segment = r_util_segment_from_component(info->interest_ndnb,
                                            ic->buf[ic->n - 2],
                                            ic->buf[ic->n - 1]);
    if (NDNSHOULDLOG(ndnr, LM_8, NDNL_FINE))
        ndnr_msg(ndnr, "enumeration: requested %jd :: expected %jd", segment, es->next_segment);
    if (segment >= 0 && segment != es->next_segment) {
        // too far in the future for us to process
        if (segment > es->next_segment + (ENUM_N_COBS / 2)) {
            if (NDNSHOULDLOG(ndnr, LM_8, NDNL_FINER))
                ndnr_msg(ndnr, "enumeration: ignoring future segment requested %jd :: expected %jd", segment, es->next_segment);
            hashtb_end(e);
            return (NDN_UPCALL_RESULT_OK);
        }
        // if theres a possibility we could have it
        if (segment >= es->next_segment - ENUM_N_COBS) {
            cob = es->cob[segment % ENUM_N_COBS];
            if (cob &&
                ndn_content_matches_interest(cob->buf, cob->length, 1, NULL,
                                             info->interest_ndnb, info->pi->offset[NDN_PI_E], info->pi)) {
                    if (NDNSHOULDLOG(ndnr, LM_8, NDNL_FINER))
                        ndnr_msg(ndnr, "enumeration: putting cob for out-of-order segment %jd",
                                 segment);
                    ndn_put(info->h, cob->buf, cob->length);
                    es->cob_deferred[segment % ENUM_N_COBS] = 0;
                    if (es->active == ES_ACTIVE_PENDING_INACTIVE) {
                        for (i = 0, cobs_deferred = 0; i < ENUM_N_COBS; i++) {
                            cobs_deferred += es->cob_deferred[i];
                        }
                        if (cobs_deferred == 0)
                            goto EnumerationComplete;
                    }
                    hashtb_end(e);
                    return (NDN_UPCALL_RESULT_INTEREST_CONSUMED);
                }
        }
    }
NextSegment:
    if (NDNSHOULDLOG(ndnr, blah, NDNL_FINE))
        ndnr_msg(ndnr, "enumeration: generating segment %jd", es->next_segment);
    es->lastuse_sec = ndnr->sec;
    es->lastuse_usec = ndnr->usec;
    while (es->content != NULL &&
           r_store_content_matches_interest_prefix(ndnr, es->content,
                                                   es->interest->buf,
                                                   es->interest->length)) {
        int save = es->reply_body->length;
        ndnb_element_begin(es->reply_body, NDN_DTAG_Link);
        ndnb_element_begin(es->reply_body, NDN_DTAG_Name);
        ndnb_element_end(es->reply_body); /* </Name> */
        res = r_store_name_append_components(es->reply_body, ndnr, es->content, es->interest_comps->n - 1, 1);
        ndnb_element_end(es->reply_body); /* </Link> */
        if (res == 0) {
            /* The name matched exactly, need to skip. */
            es->reply_body->length = save;
            es->content = r_store_next_child_at_level(ndnr, es->content, es->interest_comps->n - 1);
            continue;
        }
        if (res != 1) {
            ndnr_debug_ndnb(ndnr, __LINE__, "oops", NULL, es->interest->buf, es->interest->length);
            ndnr_debug_content(ndnr, __LINE__, "oops", NULL, es->content);
            abort();
        }
        es->content = r_store_next_child_at_level(ndnr, es->content, es->interest_comps->n - 1);
        if (es->reply_body->length >= 4096) {
            result_name = ndn_charbuf_create();
            ndn_charbuf_append_charbuf(result_name, es->name);
            ndn_name_append_numeric(result_name, NDN_MARKER_SEQNUM, es->next_segment);
            sp.freshness = 60;
            cob = es->cob[es->next_segment % ENUM_N_COBS];
            if (cob == NULL) {
                cob = ndn_charbuf_create();
                es->cob[es->next_segment % ENUM_N_COBS] = cob;
            }
            cob->length = 0;
            res = ndn_sign_content(info->h, cob, result_name, &sp,
                                   es->reply_body->buf, 4096);
            ndn_charbuf_destroy(&result_name);
            if (segment == -1 || segment == es->next_segment) {
                if (NDNSHOULDLOG(ndnr, blah, NDNL_FINER))
                    ndnr_msg(ndnr, "enumeration: putting cob for segment %jd", es->next_segment);
                ndn_put(info->h, cob->buf, cob->length);
            } else {
                es->cob_deferred[es->next_segment % ENUM_N_COBS] = 1;
            }
            es->next_segment++;
            memmove(es->reply_body->buf, es->reply_body->buf + 4096, es->reply_body->length - 4096);
            es->reply_body->length -= 4096;
            if (segment >= es->next_segment)
                 goto NextSegment;
            hashtb_end(e);
            return (NDN_UPCALL_RESULT_INTEREST_CONSUMED);
        }
    }
    // we will only get here if we are finishing an in-progress enumeration
    ndnb_element_end(es->reply_body); /* </Collection> */
    result_name = ndn_charbuf_create();
    ndn_charbuf_append_charbuf(result_name, es->name);
    ndn_name_append_numeric(result_name, NDN_MARKER_SEQNUM, es->next_segment);
    sp.freshness = 60;
    sp.sp_flags |= NDN_SP_FINAL_BLOCK;
    cob = es->cob[es->next_segment % ENUM_N_COBS];
    if (cob == NULL) {
        cob = ndn_charbuf_create();
        es->cob[es->next_segment % ENUM_N_COBS] = cob;
    }
    cob->length = 0;
    res = ndn_sign_content(info->h, cob, result_name, &sp, es->reply_body->buf,
                           es->reply_body->length);
    ndn_charbuf_destroy(&result_name);    
    if (NDNSHOULDLOG(ndnr, blah, NDNL_FINER))
        ndnr_msg(ndnr, "enumeration: putting final cob for segment %jd", es->next_segment);
    ndn_put(info->h, cob->buf, cob->length);
    es->cob_deferred[es->next_segment % ENUM_N_COBS] = 0;
    for (i = 0, cobs_deferred = 0; i < ENUM_N_COBS; i++) {
        cobs_deferred += es->cob_deferred[i];
    }
    if (cobs_deferred > 0) {
        if (NDNSHOULDLOG(ndnr, blah, NDNL_FINER))
            ndnr_msg(ndnr, "enumeration: %d pending cobs, inactive pending complete",
                     cobs_deferred);
        es->active = ES_ACTIVE_PENDING_INACTIVE;
        hashtb_end(e);
        return (NDN_UPCALL_RESULT_INTEREST_CONSUMED);
    }
EnumerationComplete:
    if (NDNSHOULDLOG(ndnr, blah, NDNL_FINER))
        ndnr_msg(ndnr, "enumeration: inactive", es->next_segment);
    // The enumeration is complete, free charbufs but leave the name.
    es->active = ES_INACTIVE;
    ndn_charbuf_destroy(&es->interest);
    ndn_charbuf_destroy(&es->reply_body);
    for (i = 0; i < ENUM_N_COBS; i++)
        ndn_charbuf_destroy(&es->cob[i]);
    ndn_indexbuf_destroy(&es->interest_comps);
    hashtb_end(e);
    return(NDN_UPCALL_RESULT_INTEREST_CONSUMED);
}

void
r_proto_dump_enums(struct ndnr_handle *ndnr)
{
    struct enum_state *es = NULL;
    struct hashtb_enumerator enumerator = {0};
    struct hashtb_enumerator *e = &enumerator;
    
    for (hashtb_start(ndnr->enum_state_tab, e); e->data != NULL; hashtb_next(e)) {
        es = e->data;
        ndnr_msg(ndnr, "Enumeration active: %d, next segment %d, cookie %u",
                 es->active, es->next_segment, es->starting_cookie);
        ndnr_debug_ndnb(ndnr, __LINE__, "     enum name", NULL,
                        es->name->buf, es->name->length);
        
    }  
    hashtb_end(e);
}

static enum ndn_upcall_res
r_proto_bulk_import(struct ndn_closure *selfp,
                          enum ndn_upcall_kind kind,
                          struct ndn_upcall_info *info,
                          int marker_comp)
{
    enum ndn_upcall_res ans = NDN_UPCALL_RESULT_ERR;
    struct ndnr_handle *ndnr = NULL;
    struct ndn_charbuf *filename = NULL;
    struct ndn_charbuf *filename2 = NULL;
    const unsigned char *mstart = NULL;
    size_t mlength;
    struct ndn_indexbuf *ic = NULL;
    struct ndn_charbuf *msg = NULL;
    struct ndn_charbuf *name = NULL;
    struct ndn_charbuf *reply_body = NULL;
    struct ndn_signing_params sp = NDN_SIGNING_PARAMS_INIT;
    const char *infostring = "OK";
    int res;
    
    ndnr = (struct ndnr_handle *)selfp->data;
    ndn_name_comp_get(info->interest_ndnb, info->interest_comps, marker_comp,
                      &mstart, &mlength);
    if (mlength <= strlen(REPO_AF) + 1 || mstart[strlen(REPO_AF)] != '~') {
        infostring = "missing or malformed bulk import name component";
        ndnr_msg(ndnr, "r_proto_bulk_import: %s", infostring);
        goto Reply;
    }
    mstart += strlen(REPO_AF) + 1;
    mlength -= (strlen(REPO_AF) + 1);
    if (memchr(mstart, '/', mlength) != NULL) {
        infostring = "bulk import filename must not include directory";
        ndnr_msg(ndnr, "r_proto_bulk_import: %s", infostring);
        goto Reply;
    }
    filename = ndn_charbuf_create();
    ndn_charbuf_append_string(filename, "import/");
    ndn_charbuf_append(filename, mstart, mlength);
    res = r_init_map_and_process_file(ndnr, filename, 0);
    if (res == 1) {
        infostring = "unable to open bulk import file";
        ndnr_msg(ndnr, "r_proto_bulk_import: %s", infostring);
        goto Reply;
    }
    if (res < 0) {
        infostring = "error parsing bulk import file";
        ndnr_msg(ndnr, "r_proto_bulk_import: %s", infostring);
        goto Reply;
    }
    /* we think we can process it */
    filename->length = 0;
    ndn_charbuf_putf(filename, "%s/import/", ndnr->directory);
    ndn_charbuf_append(filename, mstart, mlength);
    filename2 = ndn_charbuf_create();
    ndn_charbuf_putf(filename2, "%s/import/.", ndnr->directory);
    ndn_charbuf_append(filename2, mstart, mlength);
    res = rename(ndn_charbuf_as_string(filename),
                 ndn_charbuf_as_string(filename2));
    if (res < 0) {
        infostring = "error renaming bulk import file";
        ndnr_msg(ndnr, "r_proto_bulk_import: %s", infostring);
        goto Reply;        
    }
    filename->length = 0;
    ndn_charbuf_append_string(filename, "import/.");
    ndn_charbuf_append(filename, mstart, mlength);
    res = r_init_map_and_process_file(ndnr, filename, 1);
    if (res < 0) {
        infostring = "error merging bulk import file";
        ndnr_msg(ndnr, "r_proto_bulk_import: %s", infostring);
        // fall through and unlink anyway
    }
    if (NDNSHOULDLOG(ndnr, sdfdf, NDNL_FINE))
        ndnr_msg(ndnr, "unlinking bulk import file %s", ndn_charbuf_as_string(filename2));   
    unlink(ndn_charbuf_as_string(filename2));

Reply:
    /* Generate our reply */
    name = ndn_charbuf_create();
    ndn_name_init(name);
    ic = info->interest_comps;
    ndn_name_append_components(name, info->interest_ndnb, ic->buf[0], ic->buf[ic->n - 1]);

    msg = ndn_charbuf_create();
    reply_body = ndn_charbuf_create();
    r_proto_append_repo_info(ndnr, reply_body, NULL, infostring);
    sp.freshness = 12; /* Seconds */
    res = ndn_sign_content(info->h, msg, name, &sp,
                           reply_body->buf, reply_body->length);
    if (res < 0)
        goto Bail;
    res = ndn_put(info->h, msg->buf, msg->length);
    if (res < 0) {
        ndnr_debug_ndnb(ndnr, __LINE__, "r_proto_bulk_import ndn_put FAILED", NULL,
                        msg->buf, msg->length);
        goto Bail;
    }
    ans = NDN_UPCALL_RESULT_INTEREST_CONSUMED;

Bail:
    if (filename != NULL) ndn_charbuf_destroy(&filename);
    if (filename2 != NULL) ndn_charbuf_destroy(&filename2);
    if (name != NULL) ndn_charbuf_destroy(&name);
    if (msg != NULL) ndn_charbuf_destroy(&msg);
    if (reply_body != NULL) ndn_charbuf_destroy(&reply_body);
    return (ans);
}

/* Construct a charbuf with an encoding of a Policy object 
 *
 *  <xs:complexType name="PolicyType">
 *      <xs:sequence>
 *      <xs:element name="PolicyVersion" type="xs:string"/> 
 *      <xs:element name="LocalName" type="xs:string"/>
 *      <xs:element name="GlobalPrefix" type="xs:string"/>
 *  <!-- 0 or more names -->
 *      <xs:element name="Namespace" type="xs:string" minOccurs="0" maxOccurs="unbounded"/>
 *      </xs:sequence>
 *  </xs:complexType>
 */ 
PUBLIC int
r_proto_policy_append_basic(struct ndnr_handle *ndnr,
                            struct ndn_charbuf *policy,
                            const char *version, const char *local_name,
                            const char *global_prefix)
{
    int res;
    res = ndnb_element_begin(policy, NDN_DTAG_Policy);
    res |= ndnb_tagged_putf(policy, NDN_DTAG_PolicyVersion, "%s", version);
    res |= ndnb_tagged_putf(policy, NDN_DTAG_LocalName, "%s", local_name);
    res |= ndnb_tagged_putf(policy, NDN_DTAG_GlobalPrefix, "%s", global_prefix);
    res |= ndnb_element_end(policy);
    return (res);
}
PUBLIC int
r_proto_policy_append_namespace(struct ndnr_handle *ndnr,
                                struct ndn_charbuf *policy,
                                const char *namespace)
{
    int res;
    if (policy->length < 2)
        return(-1);
    policy->length--;   /* remove the closer */
    res = ndnb_tagged_putf(policy, NDN_DTAG_Namespace, "%s", namespace);
    ndnb_element_end(policy);
    return(res);
}

/**
 * Parse a ndnb-encoded policy content object and fill in a ndn_parsed_policy
 * structure as the result.
 */
PUBLIC int
r_proto_parse_policy(struct ndnr_handle *ndnr, const unsigned char *buf, size_t length,
                     struct ndnr_parsed_policy *pp)
{
    int res = 0;
    struct ndn_buf_decoder decoder;
    struct ndn_buf_decoder *d = ndn_buf_decoder_start(&decoder, buf,
                                                      length);
    if (ndn_buf_match_dtag(d, NDN_DTAG_Policy)) {
        ndn_buf_advance(d);
        pp->policy_version_offset = ndn_parse_tagged_string(d, NDN_DTAG_PolicyVersion, pp->store);
        pp->local_name_offset = ndn_parse_tagged_string(d, NDN_DTAG_LocalName, pp->store);
        pp->global_prefix_offset = ndn_parse_tagged_string(d, NDN_DTAG_GlobalPrefix, pp->store);
        pp->namespaces->n = 0;
        while (ndn_buf_match_dtag(d, NDN_DTAG_Namespace)) {
            ndn_indexbuf_append_element(pp->namespaces, ndn_parse_tagged_string(d, NDN_DTAG_Namespace, pp->store));
        }
        ndn_buf_check_close(d);
    } else {
        return(-1);
    }
    return (res);
}

/**
 * Initiate a key fetch if necessary.
 * @returns -1 if error or no name, 0 if fetch was issued, 1 if already stored.
 */
int
r_proto_initiate_key_fetch(struct ndnr_handle *ndnr,
                           const unsigned char *msg,
                           struct ndn_parsed_ContentObject *pco,
                           int use_link,
                           ndnr_cookie a)
{
    /* 
     * Create a new interest in the key name, set up a callback that will
     * insert the key into repo.
     */
    int res;
    struct ndn_charbuf *key_name = NULL;
    struct ndn_closure *key_closure = NULL;
    struct ndn_charbuf *templ = NULL;
    struct ndnr_expect_content *expect_content = NULL;
    const unsigned char *namestart = NULL;
    int namelen = 0;
    int keynamelen;
    int i;
    
    keynamelen = (pco->offset[NDN_PCO_E_KeyName_Name] -
                  pco->offset[NDN_PCO_B_KeyName_Name]);
    if (use_link) {
        /* Try to follow a link instead of using keyname */
        if (pco->type == NDN_CONTENT_LINK) {
            /* For now we only pay attention to the Name in the Link. */
            const unsigned char *data = NULL;
            size_t data_size = 0;
            struct ndn_buf_decoder decoder;
            struct ndn_buf_decoder *d;
            res = ndn_content_get_value(msg, pco->offset[NDN_PCO_E], pco,
                                        &data, &data_size);
            if (res < 0)
                return(-1);
            d = ndn_buf_decoder_start(&decoder, data, data_size);
            if (ndn_buf_match_dtag(d, NDN_DTAG_Link)) {
                int start = 0;
                int end = 0;
                ndn_buf_advance(d);
                start = d->decoder.token_index;
                ndn_parse_Name(d, NULL);
                end = d->decoder.token_index;
                ndn_buf_check_close(d);
                if (d->decoder.state < 0)
                    return(-1);
                namestart = data + start;
                namelen = end - start;
                if (namelen == keynamelen &&
                    0 == memcmp(namestart, msg + pco->offset[NDN_PCO_B_KeyName_Name], namelen)) {
                    /*
                     * The link matches the key locator. There is no point
                     * in checking two times for the same thing.
                     */
                    if (NDNSHOULDLOG(ndnr, sdfdf, NDNL_FINE))
                        ndnr_debug_ndnb(ndnr, __LINE__, "keyfetch_link_opt",
                                        NULL, namestart, namelen);
                    return(-1);
                }
            }
        }
    }
    else {
        /* Use the KeyName if present */
        namestart = msg + pco->offset[NDN_PCO_B_KeyName_Name];
        namelen = (pco->offset[NDN_PCO_E_KeyName_Name] -
                   pco->offset[NDN_PCO_B_KeyName_Name]);
    }
    /*
     * If there is no KeyName or link, provided, we can't ask, so do not bother.
     */
    if (namelen == 0 || a == 0)
        return(-1);
    key_name = ndn_charbuf_create();
    ndn_charbuf_append(key_name, namestart, namelen);
    /* Construct an interest complete with Name so we can do lookup */
    templ = ndn_charbuf_create();
    ndn_charbuf_append_tt(templ, NDN_DTAG_Interest, NDN_DTAG);
    ndn_charbuf_append(templ, key_name->buf, key_name->length);
    ndnb_tagged_putf(templ, NDN_DTAG_MinSuffixComponents, "%d", 1);
    ndnb_tagged_putf(templ, NDN_DTAG_MaxSuffixComponents, "%d", 3);
    if (pco->offset[NDN_PCO_B_KeyName_Pub] < pco->offset[NDN_PCO_E_KeyName_Pub]) {
        ndn_charbuf_append(templ,
                           msg + pco->offset[NDN_PCO_B_KeyName_Pub],
                           (pco->offset[NDN_PCO_E_KeyName_Pub] - 
                            pco->offset[NDN_PCO_B_KeyName_Pub]));
    }
    ndn_charbuf_append_closer(templ); /* </Interest> */
    /* See if we already have it - if so we declare we are done. */
    if (r_lookup(ndnr, templ, NULL) == 0) {
        res = 1;
        // Note - it might be that the thing we found is not really the thing
        // we were after.  For now we don't check.
    }
    else {
        /* We do not have it; need to ask */
        res = -1;
        expect_content = calloc(1, sizeof(*expect_content));
        if (expect_content == NULL)
            goto Bail;
        expect_content->ndnr = ndnr;
        expect_content->final = -1;
        for (i = 0; i < NDNR_PIPELINE; i++)
            expect_content->outstanding[i] = -1;
        /* inform r_proto_expect_content we are looking for a key. */
        expect_content->keyfetch = a;
        key_closure = calloc(1, sizeof(*key_closure));
        if (key_closure == NULL)
            goto Bail;
        key_closure->p = &r_proto_expect_content;
        key_closure->data = expect_content;
        res = ndn_express_interest(ndnr->direct_client, key_name, key_closure, templ);
        if (res >= 0) {
            if (NDNSHOULDLOG(ndnr, sdfdf, NDNL_FINE))
                ndnr_debug_ndnb(ndnr, __LINE__, "keyfetch_start",
                                NULL, templ->buf, templ->length);
            key_closure = NULL;
            expect_content = NULL;
            res = 0;
        }
    }
Bail:
    if (key_closure != NULL)
        free(key_closure);
    if (expect_content != NULL)
        free(expect_content);
    ndn_charbuf_destroy(&key_name);
    ndn_charbuf_destroy(&templ);
    return(res);
}

