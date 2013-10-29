/**
 * @file ndnr_init.h
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
 
#ifndef NDNR_INIT_DEFINED
#define NDNR_INIT_DEFINED

#include "ndnr_private.h"

struct ndnr_parsed_policy *ndnr_parsed_policy_create(void);
void ndnr_parsed_policy_destroy(struct ndnr_parsed_policy **ppp);
struct ndnr_handle *r_init_create(const char *progname,ndnr_logger logger,void *loggerdata);
void r_init_fail(struct ndnr_handle *, int, const char *, int);
void r_init_destroy(struct ndnr_handle **pndnr);
int r_init_map_and_process_file(struct ndnr_handle *h, struct ndn_charbuf *filename, int add_content);
struct ndn_charbuf *ndnr_init_policy_link_cob(struct ndnr_handle *ndnr, struct ndn *h, struct ndn_charbuf *targetname);
intmax_t r_init_confval(struct ndnr_handle *h, const char *key,
                        intmax_t lo, intmax_t hi, intmax_t deflt);
#endif
