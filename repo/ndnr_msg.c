/**
 * @file ndnr_msg.c
 *
 * Logging support for ndnr.
 * 
 * Part of ndnr -  NDNx Repository Daemon.
 *
 */

/*
 * Portions Copyright (C) 2013 Regents of the University of California.
 * 
 * Based on the CCNx C Library by PARC.
 * Copyright (C) 2008, 2009, 2011 Palo Alto Research Center, Inc.
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
 
#include <stdio.h>
#include <sys/time.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <unistd.h>

#include <ndn/ndn.h>
#include <ndn/charbuf.h>
#include <ndn/uri.h>

#include "ndnr_private.h"

#include "ndnr_msg.h"

/*
 * Translate a symbolic debug level into a numeric code.
 * Also accepts valid decimal values.
 * @returns NDNL_ code, or 1 to use built-in default, or -1 for error. 
 */
int
ndnr_msg_level_from_string(const char *s)
{
    long v;
    char *ep;
    
    if (s == NULL || s[0] == 0)
        return(1);
    if (0 == strcasecmp(s, "NONE"))
        return(NDNL_NONE);
    if (0 == strcasecmp(s, "SEVERE"))
        return(NDNL_SEVERE);
    if (0 == strcasecmp(s, "ERROR"))
        return(NDNL_ERROR);
    if (0 == strcasecmp(s, "WARNING"))
        return(NDNL_WARNING);
    if (0 == strcasecmp(s, "INFO"))
        return(NDNL_INFO);
    if (0 == strcasecmp(s, "FINE"))
        return(NDNL_FINE);
    if (0 == strcasecmp(s, "FINER"))
        return(NDNL_FINER);
    if (0 == strcasecmp(s, "FINEST"))
        return(NDNL_FINEST);
    v = strtol(s, &ep, 10);
    if (v > NDNL_FINEST || v < 0 || ep[0] != 0)
        return(-1);
    return(v);
}

/**
 *  Produce ndnr debug output.
 *  Output is produced via h->logger under the control of h->debug;
 *  prepends decimal timestamp and process identification.
 *  Caller should not supply newlines.
 *  @param      h  the ndnr handle
 *  @param      fmt  printf-like format string
 */
void
ndnr_msg(struct ndnr_handle *h, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    ndnr_vmsg(h, fmt, ap);
    va_end(ap);
}

/**
 *  Produce ndnr debug output.
 *  Output is produced via h->logger under the control of h->debug;
 *  prepends decimal timestamp and process identification.
 *  Caller should not supply newlines.
 *  @param      h  the ndnr handle
 *  @param      fmt  printf-like format string
 *  @param      ap varargs argument pointer
 */
void
ndnr_vmsg(struct ndnr_handle *h, const char *fmt, va_list ap)
{
    struct timeval t;
    struct ndn_charbuf *b;
    int res;
    time_t clock;
    if (h == NULL || h->debug == 0 || h->logger == 0)
        return;
    b = ndn_charbuf_create();
    if (b == NULL)
        return;
    gettimeofday(&t, NULL);
    if ((h->debug >= NDNL_FINE) &&
        ((h->logbreak-- < 0 && t.tv_sec != h->logtime) ||
         t.tv_sec >= h->logtime + 30)) {
            clock = t.tv_sec;
            ndn_charbuf_putf(b, "%ld.000000 ndnr[%d]: %s ____________________ %s",
                             (long)t.tv_sec, h->logpid,
                             h->portstr ? h->portstr : "",
                             ctime(&clock));
            h->logtime = t.tv_sec;
            h->logbreak = 30;
        }
    ndn_charbuf_putf(b, "%ld.%06u ndnr[%d]: %s\n",
                     (long)t.tv_sec, (unsigned)t.tv_usec, h->logpid, fmt);
    /* b should already have null termination, but use call for cleanliness */
    res = (*h->logger)(h->loggerdata, ndn_charbuf_as_string(b), ap);
    ndn_charbuf_destroy(&b);
    /* if there's no one to hear, don't make a sound */
    if (res < 0)
        h->debug = 0;
}

/**
 *  Produce a ndnr debug trace entry.
 *  Output is produced by calling ndnr_msg.
 *  @param      h  the ndnr handle
 *  @param      lineno  caller's source line number (usually __LINE__)
 *  @param      msg  a short text tag to identify the entry
 *  @param      fdholder    handle of associated fdholder; may be NULL
 *  @param      ndnb    points to ndnb-encoded Interest or ContentObject
 *  @param      ndnb_size   is in bytes
 */
void
ndnr_debug_ndnb(struct ndnr_handle *h,
                int lineno,
                const char *msg,
                struct fdholder *fdholder,
                const unsigned char *ndnb,
                size_t ndnb_size)
{
    struct ndn_charbuf *c;
    struct ndn_parsed_interest pi;
    const unsigned char *nonce = NULL;
    size_t nonce_size = 0;
    size_t i;
    
    
    if (h != NULL && h->debug == 0)
        return;
    c = ndn_charbuf_create();
    ndn_charbuf_putf(c, "debug.%d %s ", lineno, msg);
    if (fdholder != NULL)
        ndn_charbuf_putf(c, "%u ", fdholder->filedesc);
    ndn_uri_append(c, ndnb, ndnb_size, 1);
    ndn_charbuf_putf(c, " (%u bytes)", (unsigned)ndnb_size);
    if (ndn_parse_interest(ndnb, ndnb_size, &pi, NULL) >= 0) {
        const char *p = "";
        ndn_ref_tagged_BLOB(NDN_DTAG_Nonce, ndnb,
                  pi.offset[NDN_PI_B_Nonce],
                  pi.offset[NDN_PI_E_Nonce],
                  &nonce,
                  &nonce_size);
        if (nonce_size > 0) {
            ndn_charbuf_putf(c, " ");
            if (nonce_size == 12)
                p = "CCC-P-F-T-NN";
            for (i = 0; i < nonce_size; i++)
                ndn_charbuf_putf(c, "%s%02X", (*p) && (*p++)=='-' ? "-" : "", nonce[i]);
        }
    }
    ndnr_msg(h, "%s", ndn_charbuf_as_string(c));
    ndn_charbuf_destroy(&c);
}

