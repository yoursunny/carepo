/**
 * @file ndnr_dispatch.h
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
 
#ifndef NDNR_DISPATCH_DEFINED
#define NDNR_DISPATCH_DEFINED

#include "ndnr_private.h"
void r_dispatch_run(struct ndnr_handle *h);
void r_dispatch_process_internal_client_buffer(struct ndnr_handle *h);
struct content_entry *process_incoming_content(struct ndnr_handle *h, struct fdholder *fdholder,
                              unsigned char *msg, size_t size, off_t *offsetp);
void r_dispatch_process_input(struct ndnr_handle *h, int fd);
#endif

