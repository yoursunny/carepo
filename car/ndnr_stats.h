/**
 * @file ndnr_stats.h
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
 
#ifndef NDNR_STATS_DEFINED
#define NDNR_STATS_DEFINED

#include "ndnr_private.h"

void ndnr_meter_bump(struct ndnr_handle *h,struct ndnr_meter *m,unsigned amt);
void ndnr_meter_destroy(struct ndnr_meter **pm);
void ndnr_meter_init(struct ndnr_handle *h,struct ndnr_meter *m,const char *what);
struct ndnr_meter *ndnr_meter_create(struct ndnr_handle *h,const char *what);
uintmax_t ndnr_meter_total(struct ndnr_meter *m);
unsigned ndnr_meter_rate(struct ndnr_handle *h,struct ndnr_meter *m);
int ndnr_stats_handle_http_connection(struct ndnr_handle *h,struct fdholder *fdholder);

#endif
