/**
 * @file ndnr_sendq.h
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
 
#ifndef NDNR_SENDQ_DEFINED
#define NDNR_SENDQ_DEFINED

#include "ndnr_private.h"

int r_sendq_face_send_queue_insert(struct ndnr_handle *h, struct fdholder *fdholder, struct content_entry *content);
void r_sendq_content_queue_destroy(struct ndnr_handle *h, struct content_queue **pq);

#endif
