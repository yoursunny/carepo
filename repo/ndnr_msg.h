/**
 * @file ndnr_msg.h
 * 
 * Part of ndnr - NDNx Repository Daemon.
 *
 */

/*
 * Portions Copyright (C) 2013 Regents of the University of California.
 * 
 * Based on the CCNx C Library by PARC.
 * Copyright (C) 2011, 2012 Palo Alto Research Center, Inc.
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
 
#ifndef NDNR_MSG_DEFINED
#define NDNR_MSG_DEFINED

#include <ndn/loglevels.h>
#include <stdarg.h>

struct ndnr_handle;
struct fdholder;

int ndnr_msg_level_from_string(const char *s);

void ndnr_debug_ndnb(struct ndnr_handle *h,
                     int lineno,
                     const char *msg,
                     struct fdholder *fdholder,
                     const unsigned char *ndnb,
                     size_t ndnb_size);
void ndnr_msg(struct ndnr_handle *h, const char *fmt, ...);
void ndnr_vmsg(struct ndnr_handle *h, const char *fmt, va_list ap);

#endif
