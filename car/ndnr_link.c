/**
 * @file ndnr_link.c
 * 
 * Part of ndnr -  NDNx Repository Daemon.
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
 

 
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netdb.h>
#include <poll.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <netinet/in.h>

#include <ndn/bloom.h>
#include <ndn/ndn.h>
#include <ndn/ndn_private.h>
#include <ndn/charbuf.h>
#include <ndn/face_mgmt.h>
#include <ndn/hashtb.h>
#include <ndn/indexbuf.h>
#include <ndn/schedule.h>
#include <ndn/reg_mgmt.h>
#include <ndn/uri.h>

#include "ndnr_private.h"

#include "ndnr_link.h"

#include "ndnr_forwarding.h"
#include "ndnr_internal_client.h"
#include "ndnr_io.h"
#include "ndnr_link.h"
#include "ndnr_match.h"
#include "ndnr_msg.h"
#include "ndnr_sendq.h"
#include "ndnr_stats.h"
#include "ndnr_store.h"
#include "ndnr_util.h"

PUBLIC void
r_link_send_content(struct ndnr_handle *h, struct fdholder *fdholder, struct content_entry *content)
{
    if ((fdholder->flags & NDNR_FACE_NOSEND) != 0) {
        // XXX - should count this.
        return;
    }
    r_store_send_content(h, fdholder, content);
    ndnr_meter_bump(h, fdholder->meter[FM_DATO], 1);
    h->content_items_sent += 1;
}

/**
 * Send a message, which may be in two pieces.
 */
PUBLIC void
r_link_stuff_and_send(struct ndnr_handle *h, struct fdholder *fdholder,
               const unsigned char *data1, size_t size1,
               const unsigned char *data2, size_t size2,
               off_t *offsetp) {
    struct ndn_charbuf *c = NULL;
    
    if (size2 != 0 || 1 > size1 + size2) {
        c = r_util_charbuf_obtain(h);
        ndn_charbuf_append(c, data1, size1);
        if (size2 != 0)
            ndn_charbuf_append(c, data2, size2);
    }
    else {
        /* avoid a copy in this case */
        r_io_send(h, fdholder, data1, size1, offsetp);
        return;
    }
    r_io_send(h, fdholder, c->buf, c->length, offsetp);
    r_util_charbuf_release(h, c);
    return;
}

PUBLIC void
r_link_do_deferred_write(struct ndnr_handle *h, int fd)
{
    /* This only happens on connected sockets */
    ssize_t res;
    struct fdholder *fdholder = r_io_fdholder_from_fd(h, fd);
    if (fdholder == NULL)
        return;
    if ((fdholder->flags & NDNR_FACE_NDND) != 0) {
        /* The direct client has something to say. */
        if (NDNSHOULDLOG(h, xxx, NDNL_FINE))
            ndnr_msg(h, "sending deferred output from direct client");
        ndn_run(h->direct_client, 0);
        if (fdholder->outbuf != NULL)
            ndnr_msg(h, "URP r_link_do_deferred_write %d", __LINE__);
        return;
    }
    if (fdholder->outbuf != NULL) {
        ssize_t sendlen = fdholder->outbuf->length - fdholder->outbufindex;
        if (sendlen > 0) {
            res = send(fd, fdholder->outbuf->buf + fdholder->outbufindex, sendlen, 0);
            if (res == -1) {
                if (errno == EPIPE) {
                    fdholder->flags |= NDNR_FACE_NOSEND;
                    fdholder->outbufindex = 0;
                    ndn_charbuf_destroy(&fdholder->outbuf);
                    return;
                }
                ndnr_msg(h, "send: %s (errno = %d)", strerror(errno), errno);
                r_io_shutdown_client_fd(h, fd);
                return;
            }
            if (res == sendlen) {
                fdholder->outbufindex = 0;
                ndn_charbuf_destroy(&fdholder->outbuf);
                if ((fdholder->flags & NDNR_FACE_CLOSING) != 0)
                    r_io_shutdown_client_fd(h, fd);
                return;
            }
            fdholder->outbufindex += res;
            return;
        }
        fdholder->outbufindex = 0;
        ndn_charbuf_destroy(&fdholder->outbuf);
    }
    if ((fdholder->flags & NDNR_FACE_CLOSING) != 0)
        r_io_shutdown_client_fd(h, fd);
    else if ((fdholder->flags & NDNR_FACE_CONNECTING) != 0) {
        fdholder->flags &= ~NDNR_FACE_CONNECTING;
        ndnr_face_status_change(h, fdholder->filedesc);
    }
    else
        ndnr_msg(h, "ndnr:r_link_do_deferred_write: something fishy on %d", fd);
}
