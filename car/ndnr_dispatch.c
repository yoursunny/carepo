/**
 * @file ndnr_dispatch.c
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

#include <sync/SyncBase.h>

#include "ndnr_private.h"

#include "ndnr_dispatch.h"

#include "ndnr_forwarding.h"
#include "ndnr_io.h"
#include "ndnr_link.h"
#include "ndnr_match.h"
#include "ndnr_msg.h"
#include "ndnr_proto.h"
#include "ndnr_sendq.h"
#include "ndnr_stats.h"
#include "ndnr_store.h"
#include "ndnr_sync.h"
#include "ndnr_util.h"

static void
process_input_message(struct ndnr_handle *h, struct fdholder *fdholder,
                      unsigned char *msg, size_t size, int pdu_ok,
                      off_t *offsetp)
{
    struct ndn_skeleton_decoder decoder = {0};
    struct ndn_skeleton_decoder *d = &decoder;
    ssize_t dres;
    enum ndn_dtag dtag;
    struct content_entry *content = NULL;
    
    if ((fdholder->flags & NDNR_FACE_UNDECIDED) != 0) {
        fdholder->flags &= ~NDNR_FACE_UNDECIDED;
        if ((fdholder->flags & NDNR_FACE_LOOPBACK) != 0)
            fdholder->flags |= NDNR_FACE_GG;
        /* YYY This is the first place that we know that an inbound stream fdholder is speaking NDNx protocol. */
        r_io_register_new_face(h, fdholder);
    }
    d->state |= NDN_DSTATE_PAUSE;
    dres = ndn_skeleton_decode(d, msg, size);
    if (d->state < 0)
        abort(); /* cannot happen because of checks in caller */
    if (NDN_GET_TT_FROM_DSTATE(d->state) != NDN_DTAG) {
        ndnr_msg(h, "discarding unknown message; size = %lu", (unsigned long)size);
        // XXX - keep a count?
        return;
    }
    dtag = d->numval;
    switch (dtag) {
//        case NDN_DTAG_Interest:
//            process_incoming_interest(h, fdholder, msg, size);
//            return;
        case NDN_DTAG_ContentObject:
            content = process_incoming_content(h, fdholder, msg, size, offsetp);
            if (content != NULL)
                r_store_commit_content(h, content);
            return;
        default:
            break;
    }
    ndnr_msg(h, "discarding unknown message; dtag=%u, size = %lu",
             (unsigned)dtag,
             (unsigned long)size);
}

/**
 * Break up data in a face's input buffer buffer into individual messages,
 * and call process_input_message on each one.
 *
 * This is used to handle things originating from the internal client -
 * its output is input for fdholder 0.
 */
static void
process_input_buffer(struct ndnr_handle *h, struct fdholder *fdholder)
{
    unsigned char *msg;
    size_t size;
    ssize_t dres;
    struct ndn_skeleton_decoder *d;

    if (fdholder == NULL || fdholder->inbuf == NULL)
        return;
    d = &fdholder->decoder;
    msg = fdholder->inbuf->buf;
    size = fdholder->inbuf->length;
    while (d->index < size) {
        dres = ndn_skeleton_decode(d, msg + d->index, size - d->index);
        if (d->state != 0)
            break;
        process_input_message(h, fdholder, msg + d->index - dres, dres, 0, NULL);
    }
    if (d->index != size) {
        ndnr_msg(h, "protocol error on fdholder %u (state %d), discarding %d bytes",
                     fdholder->filedesc, d->state, (int)(size - d->index));
        // XXX - perhaps this should be a fatal error.
    }
    fdholder->inbuf->length = 0;
    memset(d, 0, sizeof(*d));
}

/**
 * Process the input from a socket or file.
 *
 * The fd has been found ready for input by the poll call.
 * Decide what fdholder it corresponds to, and after checking for exceptional
 * cases, receive data, parse it into ndnb-encoded messages, and call
 * process_input_message for each one.
 */
PUBLIC void
r_dispatch_process_input(struct ndnr_handle *h, int fd)
{
    struct fdholder *fdholder = NULL;
    struct fdholder *source = NULL;
    ssize_t res;
    ssize_t dres;
    ssize_t msgstart;
    unsigned char *buf;
    struct ndn_skeleton_decoder *d;
    struct sockaddr_storage sstor;
    socklen_t addrlen = sizeof(sstor);
    struct sockaddr *addr = (struct sockaddr *)&sstor;
    
    fdholder = r_io_fdholder_from_fd(h, fd);
    if (fdholder == NULL)
        return;
    if ((fdholder->flags & (NDNR_FACE_DGRAM | NDNR_FACE_PASSIVE)) == NDNR_FACE_PASSIVE) {
        r_io_accept_connection(h, fd);
        return;
    }
    if ((fdholder->flags & NDNR_FACE_NDND) != 0) {
        res = ndn_run(h->direct_client, 0);
        if (res < 0) {
            // Deal with it somehow.  Probably means ndnd went away.
            // Should schedule reconnection.
            ndnr_msg(h, "ndn_run returned error, shutting down direct client");
            r_io_shutdown_client_fd(h, fd);
        }
        return;
    }
    d = &fdholder->decoder;
    if (fdholder->inbuf == NULL) {
        fdholder->inbuf = ndn_charbuf_create();
        fdholder->bufoffset = 0;
    }
    if (fdholder->inbuf->length == 0)
        memset(d, 0, sizeof(*d));
    buf = ndn_charbuf_reserve(fdholder->inbuf, 8800);
    memset(&sstor, 0, sizeof(sstor));
    if ((fdholder->flags & NDNR_FACE_SOCKMASK) != 0) {
        res = recvfrom(fdholder->filedesc, buf, fdholder->inbuf->limit - fdholder->inbuf->length,
            /* flags */ 0, addr, &addrlen);
    }
    else {
        res = read(fdholder->filedesc, buf, fdholder->inbuf->limit - fdholder->inbuf->length);
    }
    if (res == -1)
        ndnr_msg(h, "read %u :%s (errno = %d)",
                    fdholder->filedesc, strerror(errno), errno);
    else if (res == 0 && (fdholder->flags & NDNR_FACE_DGRAM) == 0) {
        if (fd == h->active_in_fd && h->stable == 0) {
            h->stable = lseek(fd, 0, SEEK_END);
            ndnr_msg(h, "read %ju bytes", (uintmax_t)h->stable);
        }
        r_io_shutdown_client_fd(h, fd);
    }
    else {
        off_t offset = (off_t)-1;
        off_t *offsetp = NULL;
        if ((fdholder->flags & NDNR_FACE_REPODATA) != 0)
            offsetp = &offset;
        source = fdholder;
        ndnr_meter_bump(h, source->meter[FM_BYTI], res);
        source->recvcount++;
        fdholder->inbuf->length += res;
        msgstart = 0;
        if (((fdholder->flags & NDNR_FACE_UNDECIDED) != 0 &&
             fdholder->inbuf->length >= 6 &&
             0 == memcmp(fdholder->inbuf->buf, "GET ", 4))) {
            ndnr_stats_handle_http_connection(h, fdholder);
            return;
        }
        dres = ndn_skeleton_decode(d, buf, res);
        while (d->state == 0) {
            if (offsetp != NULL)
                *offsetp = fdholder->bufoffset + msgstart;
            process_input_message(h, source,
                                  fdholder->inbuf->buf + msgstart,
                                  d->index - msgstart,
                                  (fdholder->flags & NDNR_FACE_LOCAL) != 0,
                                  offsetp);
            msgstart = d->index;
            if (msgstart == fdholder->inbuf->length) {
                fdholder->inbuf->length = 0;
                fdholder->bufoffset += msgstart;
                return;
            }
            dres = ndn_skeleton_decode(d,
                    fdholder->inbuf->buf + msgstart,
                    fdholder->inbuf->length - msgstart);
        }
        fdholder->bufoffset += msgstart;
        if ((fdholder->flags & NDNR_FACE_DGRAM) != 0) {
            ndnr_msg(h, "protocol error on fdholder %u, discarding %u bytes",
                source->filedesc,
                (unsigned)(fdholder->inbuf->length - msgstart));
            fdholder->inbuf->length = 0;
            /* XXX - should probably ignore this source for a while */
            return;
        }
        else if (d->state < 0) {
            ndnr_msg(h, "protocol error on fdholder %u", source->filedesc);
            r_io_shutdown_client_fd(h, fd);
            return;
        }
        if (msgstart < fdholder->inbuf->length && msgstart > 0) {
            /* move partial message to start of buffer */
            memmove(fdholder->inbuf->buf, fdholder->inbuf->buf + msgstart,
                fdholder->inbuf->length - msgstart);
            fdholder->inbuf->length -= msgstart;
            d->index -= msgstart;
        }
    }
}

PUBLIC void
r_dispatch_process_internal_client_buffer(struct ndnr_handle *h)
{
    struct fdholder *fdholder = h->face0;
    if (fdholder == NULL)
        return;
    fdholder->inbuf = ndn_grab_buffered_output(h->internal_client);
    if (fdholder->inbuf == NULL)
        return;
    ndnr_meter_bump(h, fdholder->meter[FM_BYTI], fdholder->inbuf->length);
    process_input_buffer(h, fdholder);
    ndn_charbuf_destroy(&(fdholder->inbuf));
}
/**
 * Run the main loop of the ndnr
 */
PUBLIC void
r_dispatch_run(struct ndnr_handle *h)
{
    int i;
    int res;
    int timeout_ms = -1;
    int prev_timeout_ms = -1;
    int usec;
    int usec_direct;
    
    if (h->running < 0) {
        ndnr_msg(h, "Fatal error during initialization");
        return;
    }
    for (h->running = 1; h->running;) {
        r_dispatch_process_internal_client_buffer(h);
        usec = ndn_schedule_run(h->sched);
        usec_direct = ndn_process_scheduled_operations(h->direct_client);
        if (usec_direct < usec)
            usec = usec_direct;
        if (1) {
            /* If so requested, shut down when ndnd goes away. */
            if (ndn_get_connection_fd(h->direct_client) == -1) {
                /* XXX - since we cannot reasonably recover, always go away. */
                ndnr_msg(h, "lost connection to ndnd");
                h->running = 0;
                break;
            }
        }
        timeout_ms = (usec < 0) ? -1 : ((usec + 960) / 1000);
        if (timeout_ms == 0 && prev_timeout_ms == 0)
            timeout_ms = 1;
        r_dispatch_process_internal_client_buffer(h);
        r_store_trim(h, h->cob_limit);
        r_io_prepare_poll_fds(h);
        res = poll(h->fds, h->nfds, timeout_ms);
        prev_timeout_ms = ((res == 0) ? timeout_ms : 1);
        if (-1 == res) {
            if (errno == EINTR)
                continue;
            ndnr_msg(h, "poll: %s (errno = %d)", strerror(errno), errno);
            sleep(1);
            continue;
        }
        for (i = 0; res > 0 && i < h->nfds; i++) {
            if (h->fds[i].revents != 0) {
                res--;
                if (h->fds[i].revents & (POLLERR | POLLNVAL | POLLHUP)) {
                    if (h->fds[i].revents & (POLLIN))
                        r_dispatch_process_input(h, h->fds[i].fd);
                    else
                        r_io_shutdown_client_fd(h, h->fds[i].fd);
                    continue;
                }
                if (h->fds[i].revents & (POLLOUT))
                    r_link_do_deferred_write(h, h->fds[i].fd);
                else if (h->fds[i].revents & (POLLIN))
                    r_dispatch_process_input(h, h->fds[i].fd);
                else
                    ndnr_msg(h, "poll: UNHANDLED");
            }
        }
    }
}
