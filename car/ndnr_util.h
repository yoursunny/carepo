/**
 * @file ndnr_util.h
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
 
#ifndef NDNR_UTIL_DEFINED
#define NDNR_UTIL_DEFINED

#include "ndnr_private.h"

void r_util_gettime(const struct ndn_gettime *self,struct ndn_timeval *result);
int r_util_timecmp(long secA, unsigned usecA, long secB, unsigned usecB);
void r_util_reseed(struct ndnr_handle *h);
void r_util_indexbuf_release(struct ndnr_handle *h,struct ndn_indexbuf *c);
struct ndn_indexbuf *r_util_indexbuf_obtain(struct ndnr_handle *h);
void r_util_charbuf_release(struct ndnr_handle *h,struct ndn_charbuf *c);
struct ndn_charbuf *r_util_charbuf_obtain(struct ndnr_handle *h);
intmax_t r_util_segment_from_component(const unsigned char *ndnb, size_t start, size_t stop);
int r_util_name_comp_compare(const unsigned char *data, const struct ndn_indexbuf *indexbuf, unsigned int i, const void *val, size_t length);
#endif
