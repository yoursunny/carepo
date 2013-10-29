/**
 * @file ndnr_proto.h
 * 
 * Part of ndnr - NDNx Repository Daemon.
 *
 */

/*
 * Portions Copyright (C) 2013 Regents of the University of California.
 * 
 * Based on the CCNx C Library by PARC.
 * Copyright (C) 2011 Palo Alto Research Center, Inc.
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
 
#ifndef NDNR_PROTO_DEFINED
#define NDNR_PROTO_DEFINED

#include "ndnr_private.h"

#define REPO_SW "\xC1.R.sw"
#define REPO_SWC "\xC1.R.sw-c"
#define REPO_AF "\xC1.R.af"
#define NAME_BE "\xC1.E.be"

struct ndnr_parsed_policy {
    unsigned char version[7];
    int policy_version_offset;
    int local_name_offset;
    int global_prefix_offset;
    struct ndn_indexbuf *namespaces;
    struct ndn_charbuf *store;
};

#define NDNR_PIPELINE 4
struct ndnr_expect_content {
    struct ndnr_handle *ndnr;
    int tries; /** counter so we can give up eventually */
    int done;
    ndnr_cookie keyfetch;
    intmax_t outstanding[NDNR_PIPELINE];
    intmax_t final;
    ndn_handler expect_complete;
};


void r_proto_init(struct ndnr_handle *ndnr);
void r_proto_uri_listen(struct ndnr_handle *ndnr, struct ndn *ndn, const char *uri,
                        ndn_handler p, intptr_t intdata);
int r_proto_append_repo_info(struct ndnr_handle *ndnr,
                             struct ndn_charbuf *rinfo,
                             struct ndn_charbuf *names,
                             const char *info);
int r_proto_policy_append_basic(struct ndnr_handle *ndnr,
                                struct ndn_charbuf *policy,
                                const char *version, const char *local_name,
                                const char *global_prefix);
int r_proto_policy_append_namespace(struct ndnr_handle *ndnr,
                                    struct ndn_charbuf *policy,
                                    const char *namespace);
enum ndn_upcall_res r_proto_expect_content(struct ndn_closure *selfp,
                                           enum ndn_upcall_kind kind,
                                           struct ndn_upcall_info *info);
int
r_proto_parse_policy(struct ndnr_handle *ndnr, const unsigned char *buf, size_t length,
                     struct ndnr_parsed_policy *pp);
void r_proto_activate_policy(struct ndnr_handle *ndnr, struct ndnr_parsed_policy *pp);
void r_proto_deactivate_policy(struct ndnr_handle *ndnr, struct ndnr_parsed_policy *pp);
int r_proto_initiate_key_fetch(struct ndnr_handle *ndnr,
                               const unsigned char *msg,
                               struct ndn_parsed_ContentObject *pco,
                               int use_link,
                               ndnr_cookie a);
void r_proto_finalize_enum_state(struct hashtb_enumerator *e);
#endif
