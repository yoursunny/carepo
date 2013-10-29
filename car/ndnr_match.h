/**
 * @file ndnr_match.h
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
 
#ifndef NDNR_MATCH_DEFINED
#define NDNR_MATCH_DEFINED

#include <ndn/ndn.h>

#include "ndnr_private.h"

void r_match_consume_interest(struct ndnr_handle *h,struct propagating_entry *pe);

int r_match_match_interests(struct ndnr_handle *h,struct content_entry *content,struct ndn_parsed_ContentObject *pc,struct fdholder *fdholder,struct fdholder *from_face);
int r_match_consume_matching_interests(struct ndnr_handle *h,struct nameprefix_entry *npe,struct content_entry *content,struct ndn_parsed_ContentObject *pc,struct fdholder *fdholder);

#endif
