/**
 * @file ndnr_store.h
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
 
#ifndef NDNR_STORE_DEFINED
#define NDNR_STORE_DEFINED

#include <ndn/ndn.h>
#include <ndn/hashtb.h>

#include "ndnr_private.h"

void r_store_init(struct ndnr_handle *h);
int r_store_final(struct ndnr_handle *h, int stable);
void r_store_set_content_timer(struct ndnr_handle *h,struct content_entry *content,struct ndn_parsed_ContentObject *pco);
void r_store_mark_stale(struct ndnr_handle *h,struct content_entry *content);
struct content_entry *r_store_next_child_at_level(struct ndnr_handle *h,struct content_entry *content,int level);
struct content_entry *r_store_content_next(struct ndnr_handle *h,struct content_entry *content);
int r_store_content_matches_interest_prefix(struct ndnr_handle *h,struct content_entry *content,const unsigned char *interest_msg, size_t interest_size);
struct content_entry *r_store_find_first_match_candidate(struct ndnr_handle *h,const unsigned char *interest_msg,const struct ndn_parsed_interest *pi);
ndnr_cookie r_store_enroll_content(struct ndnr_handle *h,struct content_entry *content);
struct content_entry *r_store_content_from_accession(struct ndnr_handle *h, ndnr_accession accession);
struct content_entry *r_store_content_from_cookie(struct ndnr_handle *h, ndnr_cookie cookie);

struct content_entry *r_store_lookup(struct ndnr_handle *h, const unsigned char *msg, const struct ndn_parsed_interest *pi, struct ndn_indexbuf *comps);
struct content_entry *r_store_lookup_ndnb(struct ndnr_handle *h, const unsigned char *namish, size_t size);
int r_store_content_field_access(struct ndnr_handle *h, struct content_entry *content, enum ndn_dtag dtag, const unsigned char **bufp, size_t *sizep);
void r_store_send_content(struct ndnr_handle *h, struct fdholder *fdholder, struct content_entry *content);
int r_store_name_append_components(struct ndn_charbuf *dst, struct ndnr_handle *h, struct content_entry *content, int skip, int count);
int r_store_content_flags(struct content_entry *content);
int r_store_content_change_flags(struct content_entry *content, int set, int clear);
int r_store_commit_content(struct ndnr_handle *h, struct content_entry *content);
void r_store_forget_content(struct ndnr_handle *h, struct content_entry **pentry);
void ndnr_debug_content(struct ndnr_handle *h, int lineno, const char *msg,
                        struct fdholder *fdholder,
                        struct content_entry *content);
int r_store_set_accession_from_offset(struct ndnr_handle *h, struct content_entry *content, struct fdholder *fdholder, off_t offset);
int r_store_content_trim(struct ndnr_handle *h, struct content_entry *content);
void r_store_trim(struct ndnr_handle *h, unsigned long limit);
ndnr_cookie r_store_content_cookie(struct ndnr_handle *h, struct content_entry *content);
ndnr_accession r_store_content_accession(struct ndnr_handle *h, struct content_entry *content);
const unsigned char *r_store_content_base(struct ndnr_handle *h, struct content_entry *content);
size_t r_store_content_size(struct ndnr_handle *h, struct content_entry *content);
void r_store_index_needs_cleaning(struct ndnr_handle *h);
struct ndn_charbuf *r_store_content_flatname(struct ndnr_handle *h, struct content_entry *content);
#endif
