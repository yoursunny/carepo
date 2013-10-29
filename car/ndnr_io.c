/**
 * @file ndnr_io.c
 * 
 * Part of ndnr -  NDNx Repository Daemon.
 *
 */

/*
 * Portions Copyright (C) 2013 Regents of the University of California.
 * 
 * Based on the CCNx C Library by PARC.
 * Copyright (C) 2011, 2013 Palo Alto Research Center, Inc.
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

#include "ndnr_io.h"

#include "ndnr_forwarding.h"
#include "ndnr_internal_client.h"
#include "ndnr_link.h"
#include "ndnr_msg.h"
#include "ndnr_sendq.h"
#include "ndnr_stats.h"

/**
 * Looks up a fdholder based on its filedesc (private).
 */
PUBLIC struct fdholder *
r_io_fdholder_from_fd(struct ndnr_handle *h, unsigned filedesc)
{
    unsigned slot = filedesc;
    struct fdholder *fdholder = NULL;
    if (slot < h->face_limit) {
        fdholder = h->fdholder_by_fd[slot];
        if (fdholder != NULL && fdholder->filedesc != filedesc)
            fdholder = NULL;
    }
    return(fdholder);
}

/**
 * Looks up a fdholder based on its filedesc.
 */
PUBLIC struct fdholder *
ndnr_r_io_fdholder_from_fd(struct ndnr_handle *h, unsigned filedesc)
{
    return(r_io_fdholder_from_fd(h, filedesc));
}

/**
 * Assigns the filedesc for a nacent fdholder,
 * calls r_io_register_new_face() if successful.
 */
PUBLIC int
r_io_enroll_face(struct ndnr_handle *h, struct fdholder *fdholder)
{
    unsigned i = fdholder->filedesc;
    unsigned n = h->face_limit;
    struct fdholder **a = h->fdholder_by_fd;
    if (i < n && a[i] == NULL) {
        if (a[i] == NULL)
            goto use_i;
        abort();
    }
    if (i > 65535)
        abort();
    a = realloc(a, (i + 1) * sizeof(struct fdholder *));
    if (a == NULL)
        return(-1); /* ENOMEM */
    h->face_limit = i + 1;
    while (n < h->face_limit)
        a[n++] = NULL;
    h->fdholder_by_fd = a;
use_i:
    a[i] = fdholder;
    if (i == 0)
        h->face0 = fdholder; /* This one is special */
    fdholder->filedesc = i;
    fdholder->meter[FM_BYTI] = ndnr_meter_create(h, "bytein");
    fdholder->meter[FM_BYTO] = ndnr_meter_create(h, "byteout");
    fdholder->meter[FM_INTI] = ndnr_meter_create(h, "intrin");
    fdholder->meter[FM_INTO] = ndnr_meter_create(h, "introut");
    fdholder->meter[FM_DATI] = ndnr_meter_create(h, "datain");
    fdholder->meter[FM_DATO] = ndnr_meter_create(h, "dataout");
    r_io_register_new_face(h, fdholder);
    return (fdholder->filedesc);
}

/**
 * Close an open file descriptor quietly.
 */
static void
close_fd(int *pfd)
{
    if (*pfd != -1) {
        close(*pfd);
        *pfd = -1;
    }
}

/**
 * Close an open file descriptor, and grumble about it.
 */
/* unused */ void
ndnr_close_fd(struct ndnr_handle *h, unsigned filedesc, int *pfd)
{
    int res;
    
    if (*pfd != -1) {
        int linger = 0;
        setsockopt(*pfd, SOL_SOCKET, SO_LINGER,
                   &linger, sizeof(linger));
        res = close(*pfd);
        if (res == -1)
            ndnr_msg(h, "close failed for fdholder %u fd=%d: %s (errno=%d)",
                     filedesc, *pfd, strerror(errno), errno);
        else if (NDNSHOULDLOG(h, io, NDNL_FINE))
            ndnr_msg(h, "closing fd %d while finalizing fdholder %u", *pfd, filedesc);
        *pfd = -1;
    }
}


/**
 * Initialize the fdholder flags based upon the addr information
 * and the provided explicit setflags.
 */
static void
init_face_flags(struct ndnr_handle *h, struct fdholder *fdholder, int setflags)
{
    const struct sockaddr *addr;
    
    if ((setflags & (NDNR_FACE_REPODATA)) != 0) {
        fdholder->flags |= setflags;
        return;
    }
    addr = (void *)fdholder->name->buf;
    if (addr->sa_family == AF_INET6) {
        const struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)addr;
        fdholder->flags |= NDNR_FACE_INET6;
#ifdef IN6_IS_ADDR_LOOPBACK
        if (IN6_IS_ADDR_LOOPBACK(&addr6->sin6_addr))
            fdholder->flags |= NDNR_FACE_LOOPBACK;
#endif
    }
    else if (addr->sa_family == AF_INET) {
        const struct sockaddr_in *addr4 = (struct sockaddr_in *)addr;
        const unsigned char *rawaddr;
        rawaddr = (const unsigned char *)&addr4->sin_addr.s_addr;
        fdholder->flags |= NDNR_FACE_INET;
        if (rawaddr[0] == 127)
            fdholder->flags |= NDNR_FACE_LOOPBACK;
        else {
            /* If our side and the peer have the same address, consider it loopback */
            /* This is the situation inside of FreeBSD jail. */
            struct sockaddr_in myaddr;
            socklen_t myaddrlen = sizeof(myaddr);
            if (0 == getsockname(fdholder->filedesc, (struct sockaddr *)&myaddr, &myaddrlen)) {
                if (addr4->sin_addr.s_addr == myaddr.sin_addr.s_addr)
                    fdholder->flags |= NDNR_FACE_LOOPBACK;
            }
        }
    }
    else if (addr->sa_family == AF_UNIX)
        fdholder->flags |= (NDNR_FACE_GG | NDNR_FACE_LOCAL);
    fdholder->flags |= setflags;
}

/**
 * Make a new fdholder corresponding to the fd
 */
PUBLIC struct fdholder *
r_io_record_fd(struct ndnr_handle *h, int fd,
                  void *who, socklen_t wholen,
                  int setflags)
{
    int res;
    struct fdholder *fdholder = NULL;
    
    res = fcntl(fd, F_SETFL, O_NONBLOCK);
    if (res == -1)
        ndnr_msg(h, "fcntl: %s", strerror(errno));
    fdholder = calloc(1, sizeof(*fdholder));
    
    
    if (fdholder == NULL)
        return(fdholder);
    fdholder->name = ndn_charbuf_create();
    if (fdholder->name == NULL)
        abort();
    if (who != NULL)
        ndn_charbuf_append(fdholder->name, who, wholen);
    fdholder->filedesc = fd;
    init_face_flags(h, fdholder, setflags);
    res = r_io_enroll_face(h, fdholder);
    if (res == -1) {
        ndn_charbuf_destroy(&fdholder->name);
        free(fdholder);
        fdholder = NULL;
    }
    return(fdholder);
}

/**
 * Accept an incoming DGRAM_STREAM connection, creating a new fdholder.
 * @returns fd of new socket, or -1 for an error.
 */
PUBLIC int
r_io_accept_connection(struct ndnr_handle *h, int listener_fd)
{
    struct sockaddr_storage who;
    socklen_t wholen = sizeof(who);
    int fd;
    struct fdholder *fdholder;

    fd = accept(listener_fd, (struct sockaddr *)&who, &wholen);
    if (fd == -1) {
        ndnr_msg(h, "accept: %s", strerror(errno));
        return(-1);
    }
    fdholder = r_io_record_fd(h, fd,
                            (struct sockaddr *)&who, wholen,
                            NDNR_FACE_UNDECIDED);
    if (fdholder == NULL)
        close_fd(&fd);
    else if (NDNSHOULDLOG(h, io, NDNL_INFO))
        ndnr_msg(h, "accepted client fd=%d id=%u", fd, fdholder->filedesc);
    return(fd);
}

PUBLIC int
r_io_open_repo_data_file(struct ndnr_handle *h, const char *name, int output)
{
    struct ndn_charbuf *temp = NULL;
    int fd = -1;
    struct fdholder *fdholder = NULL;

    temp = ndn_charbuf_create();
    ndn_charbuf_putf(temp, "%s/%s", h->directory, name);
    fd = open(ndn_charbuf_as_string(temp), output ? (O_CREAT | O_WRONLY | O_APPEND) : O_RDONLY, 0666);
    if (fd == -1) {
        if (NDNSHOULDLOG(h, sdf, NDNL_FINE))
            ndnr_msg(h, "open(%s): %s", ndn_charbuf_as_string(temp), strerror(errno));
        ndn_charbuf_destroy(&temp);
        return(-1);
    }
    fdholder = r_io_record_fd(h, fd,
                            temp->buf, temp->length,
                            NDNR_FACE_REPODATA | (output ? NDNR_FACE_NORECV : NDNR_FACE_NOSEND));
    if (fdholder == NULL)
        close_fd(&fd);
    else {
        if (!output) {
            /* Use a larger buffer for indexing an existing repo file */
            if (fdholder->inbuf == NULL) {
                fdholder->inbuf = ndn_charbuf_create();
                fdholder->bufoffset = 0;
            }
            if (fdholder->inbuf != NULL)
                ndn_charbuf_reserve(fdholder->inbuf, 256 * 1024);
        }
        if (NDNSHOULDLOG(h, sdf, NDNL_INFO))
            ndnr_msg(h, "opened fd=%d file=%s", fd, ndn_charbuf_as_string(temp));
    }
    ndn_charbuf_destroy(&temp);
    return(fd);
}


PUBLIC int
r_io_repo_data_file_fd(struct ndnr_handle *h, unsigned repofile, int output)
{
    if (repofile != 1)
        return(-1);
    if (output)
        return(-1);
    if (h->repofile1_fd > 0)
        return(h->repofile1_fd);
    h->repofile1_fd = r_io_open_repo_data_file(h, "repoFile1", 0);
    return(h->repofile1_fd);
}

PUBLIC void
r_io_shutdown_client_fd(struct ndnr_handle *h, int fd)
{
    struct fdholder *fdholder = NULL;
    enum cq_delay_class c;
    int m;
    int res;
    
    fdholder = r_io_fdholder_from_fd(h, fd);
    if (fdholder == NULL) {
        ndnr_msg(h, "no fd holder for fd %d", fd);
        return;
    }
    if (fdholder == h->face0)
        (res = 0, h->face0 = NULL);
    else if ((fdholder->flags & NDNR_FACE_NDND))
        res = ndn_disconnect(h->direct_client);
    else
        res = close(fd);
    if (NDNSHOULDLOG(h, sdfdf, NDNL_INFO))
        ndnr_msg(h, "shutdown client fd=%d", fd);
    ndn_charbuf_destroy(&fdholder->inbuf);
    ndn_charbuf_destroy(&fdholder->outbuf);
    for (c = 0; c < NDN_CQ_N; c++)
        r_sendq_content_queue_destroy(h, &(fdholder->q[c]));
    for (m = 0; m < NDNR_FACE_METER_N; m++)
        ndnr_meter_destroy(&fdholder->meter[m]);
    if (h->fdholder_by_fd[fd] != fdholder) abort();
    h->fdholder_by_fd[fd] = NULL;
    ndn_charbuf_destroy(&fdholder->name);
    free(fdholder);
    if (h->active_in_fd == fd)
        h->active_in_fd = -1;
    if (h->active_out_fd == fd)
        h->active_out_fd = -1;
    if (h->repofile1_fd == fd)
        h->repofile1_fd = -1;
    // r_fwd_reap_needed(h, 250000);
}

/**
 * Destroys the fdholder identified by filedesc.
 * @returns 0 for success, -1 for failure.
 */
PUBLIC int
r_io_destroy_face(struct ndnr_handle *h, unsigned filedesc)
{
    r_io_shutdown_client_fd(h, filedesc);
    return(0);
}

/**
 * Called when a fdholder is first created, and (perhaps) a second time in the case
 * that a fdholder transitions from the undecided state.
 */
PUBLIC void
r_io_register_new_face(struct ndnr_handle *h, struct fdholder *fdholder)
{
    if (fdholder->filedesc != 0 && (fdholder->flags & (NDNR_FACE_UNDECIDED | NDNR_FACE_PASSIVE)) == 0) {
        ndnr_face_status_change(h, fdholder->filedesc);
    }
}

/**
 * Handle errors after send() or sendto().
 * @returns -1 if error has been dealt with, or 0 to defer sending.
 */
static int
handle_send_error(struct ndnr_handle *h, int errnum, struct fdholder *fdholder,
                  const void *data, size_t size)
{
    int res = -1;
    if (errnum == EAGAIN) {
        res = 0;
    }
    else if (errnum == EPIPE) {
        fdholder->flags |= NDNR_FACE_NOSEND;
        fdholder->outbufindex = 0;
        ndn_charbuf_destroy(&fdholder->outbuf);
    }
    else {
        ndnr_msg(h, "send/write to fd %u failed: %s (errno = %d)",
                 fdholder->filedesc, strerror(errnum), errnum);
        if (errnum == EISCONN || errnum == EFBIG || errnum == ENOSPC)
            res = 0;
    }
    return(res);
}

static int
sending_fd(struct ndnr_handle *h, struct fdholder *fdholder)
{
    return(fdholder->filedesc);
}

/**
 * Send data to the fdholder.
 *
 * No direct error result is provided; the fdholder state is updated as needed.
 */
PUBLIC void
r_io_send(struct ndnr_handle *h,
          struct fdholder *fdholder,
          const void *data, size_t size,
          off_t *offsetp)
{
    ssize_t res;
    off_t offset = -1;
    
    if (offsetp != NULL)
        *offsetp = (off_t)-1;
    if ((fdholder->flags & NDNR_FACE_NOSEND) != 0)
        return;
    if (fdholder->outbuf != NULL) {
        ndn_charbuf_append(fdholder->outbuf, data, size);
        return;
    }
    if (fdholder == h->face0) {
        ndnr_meter_bump(h, fdholder->meter[FM_BYTO], size);
        ndn_dispatch_message(h->internal_client, (void *)data, size);
        r_dispatch_process_internal_client_buffer(h);
        return;
    }
    if ((fdholder->flags & NDNR_FACE_NDND) != 0) {
        /* Writes here need to go via the direct client's handle. */
        ndnr_meter_bump(h, fdholder->meter[FM_BYTO], size);
        res = ndn_put(h->direct_client, data, size);
        if (res < 0 && NDNSHOULDLOG(h, r_io_send, NDNL_WARNING))
            ndnr_msg(h, "ndn_put failed");
        if (res == 1 && NDNSHOULDLOG(h, r_io_send, NDNL_FINEST))
            ndnr_msg(h, "ndn_put deferred output for later send");
        return;
    }
    if ((fdholder->flags & NDNR_FACE_REPODATA) != 0) {
        offset = lseek(fdholder->filedesc, 0, SEEK_END);
        if (offset == (off_t)-1) {
            ndnr_msg(h, "lseek(%d): %s", fdholder->filedesc, strerror(errno));
            return;
        }
        if (offsetp != NULL)
            *offsetp = offset;
        if (fdholder->filedesc == h->active_out_fd) {
            if (offset != h->stable && h->stable != 0)
                ndnr_msg(h, "expected file size %ju, found %ju",
                    (uintmax_t)h->stable,
                    (uintmax_t)offset);
            h->stable = offset + size;
        }
    }
    if ((fdholder->flags & NDNR_FACE_DGRAM) == 0)
        res = write(fdholder->filedesc, data, size);
    else
        res = sendto(sending_fd(h, fdholder), data, size, 0,
                     (struct sockaddr *)fdholder->name->buf,
                     fdholder->name->length);
    if (res > 0)
        ndnr_meter_bump(h, fdholder->meter[FM_BYTO], res);
    if (res == size)
        return;
    if (res == -1) {
        res = handle_send_error(h, errno, fdholder, data, size);
        if (res == -1)
            return;
    }
    if ((fdholder->flags & NDNR_FACE_DGRAM) != 0) {
        ndnr_msg(h, "sendto short");
        return;
    }
    if ((fdholder->flags & NDNR_FACE_REPODATA) != 0) {
        // need to truncate back to last known good object then exit.
        ndnr_msg(h, "Unrecoverable write error writing to repository. Content NOT stored.");
        if (ftruncate(fdholder->filedesc, offset) < 0) {
            ndnr_msg(h, "ftruncate: %s", strerror(errno));
        }
        h->running = 0;
        return;
    }
    fdholder->outbufindex = 0;
    fdholder->outbuf = ndn_charbuf_create();
    if (fdholder->outbuf == NULL) {
        ndnr_msg(h, "do_write: %s", strerror(errno));
        return;
    }
    ndn_charbuf_append(fdholder->outbuf,
                       ((const unsigned char *)data) + res, size - res);
}
/**
 * Set up the array of fd descriptors for the poll(2) call.
 *
 */
PUBLIC void
r_io_prepare_poll_fds(struct ndnr_handle *h)
{
    int i, j, nfds;
    
    for (i = 1, nfds = 0; i < h->face_limit; i++)
        if (r_io_fdholder_from_fd(h, i) != NULL)
            nfds++;
    
    if (nfds != h->nfds) {
        h->nfds = nfds;
        h->fds = realloc(h->fds, h->nfds * sizeof(h->fds[0]));
        memset(h->fds, 0, h->nfds * sizeof(h->fds[0]));
    }
    for (i = 1, j = 0; i < h->face_limit; i++) {
        struct fdholder *fdholder = r_io_fdholder_from_fd(h, i);
        if (fdholder != NULL) {
            h->fds[j].fd = fdholder->filedesc;
            h->fds[j].events = 0;
            if ((fdholder->flags & (NDNR_FACE_NORECV|NDNR_FACE_REPODATA)) == 0)
                h->fds[j].events |= POLLIN;
            if (fdholder->filedesc == h->active_in_fd)
                h->fds[j].events |= POLLIN;
            if (((fdholder->flags & NDNR_FACE_REPODATA) == 0) &&
                ((fdholder->outbuf != NULL || (fdholder->flags & NDNR_FACE_CLOSING) != 0)))
                h->fds[j].events |= POLLOUT;
             if ((fdholder->flags & NDNR_FACE_NDND) != 0) {
                 if (ndn_output_is_pending(h->direct_client)) {
                     if (NDNSHOULDLOG(h, xxx, NDNL_FINEST))
                        ndnr_msg(h, "including direct client in poll set");
                     h->fds[j].events |= POLLOUT;
                }
             }
            j++;
        }
    }
}

/**
 * Shutdown all open fds.
 */
PUBLIC void
r_io_shutdown_all(struct ndnr_handle *h)
{
    int i;
    for (i = 1; i < h->face_limit; i++) {
        if (r_io_fdholder_from_fd(h, i) != NULL)
            r_io_shutdown_client_fd(h, i);
    }
    ndnr_internal_client_stop(h);
    r_io_shutdown_client_fd(h, 0);
}
