/**
 * @file ndnr_internal_client.h
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
 
#ifndef NDNR_INTERNAL_DEFINED
#define NDNR_INTERNAL_DEFINED

#include "ndnr_private.h"

void ndnr_internal_client_stop(struct ndnr_handle *ndnr);
int ndnr_internal_client_start(struct ndnr_handle *ndnr);
void ndnr_face_status_change(struct ndnr_handle *ndnr,unsigned filedesc);
int ndnr_init_repo_keystore(struct ndnr_handle *ndnr, struct ndn *ndn);

void ndnr_direct_client_stop(struct ndnr_handle *ndnr);
int ndnr_direct_client_start(struct ndnr_handle *ndnr);

/**
 * Local interpretation of selfp->intdata
 */
#define MORECOMPS_MASK 0x007F
#define MUST_VERIFY    0x0080
#define MUST_VERIFY1   (MUST_VERIFY + 1)
#define OPER_MASK      0xFF00
#define OP_PING        0x0000
#define OP_NEWFACE     0x0200
#define OP_DESTROYFACE 0x0300
#define OP_PREFIXREG   0x0400
#define OP_SELFREG     0x0500
#define OP_UNREG       0x0600
#define OP_NOTICE      0x0700
#define OP_SERVICE     0x0800
void ndnr_uri_listen(struct ndnr_handle *ndnr, struct ndn *ndn, const char *uri,
                ndn_handler p, intptr_t intdata);
enum ndn_upcall_res ndnr_answer_req(struct ndn_closure *selfp,
                 enum ndn_upcall_kind kind,
                 struct ndn_upcall_info *info);
#endif
