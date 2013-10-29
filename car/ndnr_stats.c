/**
 * @file ndnr_stats.c
 * 
 * Statistics presentation for ndnr.
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
 
#include <sys/types.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/utsname.h>
#include <time.h>
#include <unistd.h>
#include <ndn/ndn.h>
#include <ndn/charbuf.h>
#include <ndn/coding.h>
#include <ndn/indexbuf.h>
#include <ndn/schedule.h>
#include <ndn/sockaddrutil.h>
#include <ndn/hashtb.h>
#include <ndn/uri.h>

#include "ndnr_private.h"

#include "ndnr_stats.h"
#include "ndnr_io.h"
#include "ndnr_msg.h"


#define CRLF "\r\n"
#define NL   "\n"

/**
 * Provide a way to monitor rates.
 */
struct ndnr_meter {
    uintmax_t total;
    char what[8];
    unsigned rate; /** a scale factor applies */
    unsigned lastupdate;
};

struct ndnr_stats {
    long total_interest_counts;
    long total_flood_control;      /* done propagating, still recorded */
};

static int ndnr_collect_stats(struct ndnr_handle *h, struct ndnr_stats *ans);
static struct ndn_charbuf *collect_stats_html(struct ndnr_handle *h);
static void send_http_response(struct ndnr_handle *h, struct fdholder *fdholder,
                               const char *mime_type,
                               struct ndn_charbuf *response);
static struct ndn_charbuf *collect_stats_html(struct ndnr_handle *h);
static struct ndn_charbuf *collect_stats_xml(struct ndnr_handle *h);

/* HTTP */

static const char *resp404 =
    "HTTP/1.1 404 Not Found" CRLF
    "Connection: close" CRLF CRLF;

static const char *resp405 =
    "HTTP/1.1 405 Method Not Allowed" CRLF
    "Connection: close" CRLF CRLF;

static void
ndnr_stats_http_set_debug(struct ndnr_handle *h, struct fdholder *fdholder, int level)
{
    struct ndn_charbuf *response = ndn_charbuf_create();
    
    h->debug = 1;
    ndnr_msg(h, "NDNR_DEBUG=%d", level);
    h->debug = level;
    ndn_charbuf_putf(response, "<title>NDNR_DEBUG=%d</title><tt>NDNR_DEBUG=%d</tt>" CRLF, level, level);
    send_http_response(h, fdholder, "text/html", response);
    ndn_charbuf_destroy(&response);
}

int
ndnr_stats_handle_http_connection(struct ndnr_handle *h, struct fdholder *fdholder)
{
    struct ndn_charbuf *response = NULL;
    char rbuf[16];
    int i;
    int nspace;
    int n;
    
    if (fdholder->inbuf->length < 4)
        return(-1);
    if ((fdholder->flags & NDNR_FACE_NOSEND) != 0) {
        r_io_destroy_face(h, fdholder->filedesc);
        return(-1);
    }
    n = sizeof(rbuf) - 1;
    if (fdholder->inbuf->length < n)
        n = fdholder->inbuf->length;
    for (i = 0, nspace = 0; i < n && nspace < 2; i++) {
        rbuf[i] = fdholder->inbuf->buf[i];
        if (rbuf[i] == ' ')
            nspace++;
    }
    rbuf[i] = 0;
    if (nspace < 2 && i < sizeof(rbuf) - 1)
        return(-1);
    if (0 == strcmp(rbuf, "GET / ") ||
        0 == strcmp(rbuf, "GET /? ")) {
        response = collect_stats_html(h);
        send_http_response(h, fdholder, "text/html", response);
    }
    else if (0 == strcmp(rbuf, "GET /?l=none ")) {
        ndnr_stats_http_set_debug(h, fdholder, 0);
    }
    else if (0 == strcmp(rbuf, "GET /?l=low ")) {
        ndnr_stats_http_set_debug(h, fdholder, 1);
    }
    else if (0 == strcmp(rbuf, "GET /?l=co ")) {
        ndnr_stats_http_set_debug(h, fdholder, 4);
    }
    else if (0 == strcmp(rbuf, "GET /?l=med ")) {
        ndnr_stats_http_set_debug(h, fdholder, 71);
    }
    else if (0 == strcmp(rbuf, "GET /?l=high ")) {
        ndnr_stats_http_set_debug(h, fdholder, -1);
    }
    else if (0 == strcmp(rbuf, "GET /?f=xml ")) {
        response = collect_stats_xml(h);
        send_http_response(h, fdholder, "text/xml", response);
    }
    else if (0 == strcmp(rbuf, "GET "))
        r_io_send(h, fdholder, resp404, strlen(resp404), NULL);
    else
        r_io_send(h, fdholder, resp405, strlen(resp405), NULL);
    fdholder->flags |= (NDNR_FACE_NOSEND | NDNR_FACE_CLOSING);
    ndn_charbuf_destroy(&response);
    return(0);
}

static void
send_http_response(struct ndnr_handle *h, struct fdholder *fdholder,
                   const char *mime_type, struct ndn_charbuf *response)
{
    struct linger linger = { .l_onoff = 1, .l_linger = 1 };
    char buf[128];
    int hdrlen;

    /* Set linger to prevent quickly resetting the connection on close.*/
    setsockopt(fdholder->filedesc, SOL_SOCKET, SO_LINGER, &linger, sizeof(linger));
    hdrlen = snprintf(buf, sizeof(buf),
                      "HTTP/1.1 200 OK" CRLF
                      "Content-Type: %s; charset=utf-8" CRLF
                      "Connection: close" CRLF
                      "Content-Length: %jd" CRLF CRLF,
                      mime_type,
                      (intmax_t)response->length);
    r_io_send(h, fdholder, buf, hdrlen, NULL);
    r_io_send(h, fdholder, response->buf, response->length, NULL);
}

/* Common statistics collection */

static int
ndnr_collect_stats(struct ndnr_handle *h, struct ndnr_stats *ans)
{
    struct hashtb_enumerator ee;
    struct hashtb_enumerator *e = &ee;
    long sum;
    unsigned i;
    for (sum = 0, hashtb_start(h->nameprefix_tab, e);
         e->data != NULL; hashtb_next(e)) {
        struct nameprefix_entry *npe = e->data;
        struct propagating_entry *head = &npe->pe_head;
        struct propagating_entry *p;
        for (p = head->next; p != head; p = p->next) {
            if (ndnr_r_io_fdholder_from_fd(h, p->filedesc) != NULL)
                sum += 1;
        }
    }
    ans->total_interest_counts = sum;
    hashtb_end(e);
    for (sum = 0, hashtb_start(h->propagating_tab, e);
         e->data != NULL; hashtb_next(e)) {
        struct propagating_entry *pe = e->data;
        if (pe->interest_msg == NULL)
            sum += 1;
    }
    ans->total_flood_control = sum;
    hashtb_end(e);
    /* Do a consistency check on pending interest counts */
    for (sum = 0, i = 0; i < h->face_limit; i++) {
        struct fdholder *fdholder = h->fdholder_by_fd[i];
        if (fdholder != NULL)
            sum += fdholder->pending_interests;
    }
    if (sum != ans->total_interest_counts)
        ndnr_msg(h, "ndnr_collect_stats found inconsistency %ld != %ld\n",
                 (long)sum, (long)ans->total_interest_counts);
    ans->total_interest_counts = sum;
    return(0);
}

/* HTML formatting */

static void
collect_faces_html(struct ndnr_handle *h, struct ndn_charbuf *b)
{
    int i;
    struct ndn_charbuf *nodebuf;
    
    nodebuf = ndn_charbuf_create();
    ndn_charbuf_putf(b, "<h4>Faces</h4>" NL);
    ndn_charbuf_putf(b, "<ul>");
    for (i = 0; i < h->face_limit; i++) {
        struct fdholder *fdholder = h->fdholder_by_fd[i];
        if (fdholder != NULL && (fdholder->flags & NDNR_FACE_UNDECIDED) == 0) {
            ndn_charbuf_putf(b, " <li>");
            ndn_charbuf_putf(b, "<b>fdholder:</b> %u <b>flags:</b> 0x%x",
                             fdholder->filedesc, fdholder->flags);
            ndn_charbuf_putf(b, " <b>pending:</b> %d",
                             fdholder->pending_interests);
            if (fdholder->recvcount != 0)
                ndn_charbuf_putf(b, " <b>activity:</b> %d",
                                 fdholder->recvcount);
            nodebuf->length = 0;
#if 0
            port = 0;
// XXX - fix for fdholder->name
            int port = ndn_charbuf_append_sockaddr(nodebuf, fdholder->addr);
            if (port > 0) {
                const char *node = ndn_charbuf_as_string(nodebuf);
                if ((fdholder->flags & NDNR_FACE_PASSIVE) == 0)
                    ndn_charbuf_putf(b, " <b>remote:</b> %s:%d",
                                     node, port);
                else
                    ndn_charbuf_putf(b, " <b>local:</b> %s:%d",
                                     node, port);
                if (fdholder->sendface != fdholder->filedesc &&
                    fdholder->sendface != NDN_NOFACEID)
                    ndn_charbuf_putf(b, " <b>via:</b> %u", fdholder->sendface);
            }
#endif
            ndn_charbuf_putf(b, "</li>" NL);
        }
    }
    ndn_charbuf_putf(b, "</ul>");
    ndn_charbuf_destroy(&nodebuf);
}

static void
collect_face_meter_html(struct ndnr_handle *h, struct ndn_charbuf *b)
{
    int i;
    ndn_charbuf_putf(b, "<h4>fdholder Activity Rates</h4>");
    ndn_charbuf_putf(b, "<table cellspacing='0' cellpadding='0' class='tbl' summary='fdholder activity rates'>");
    ndn_charbuf_putf(b, "<tbody>" NL);
    ndn_charbuf_putf(b, " <tr><td>        </td>\t"
                        " <td>Bytes/sec In/Out</td>\t"
                        " <td>recv data/intr sent</td>\t"
                        " <td>sent data/intr recv</td></tr>" NL);
    for (i = 0; i < h->face_limit; i++) {
        struct fdholder *fdholder = h->fdholder_by_fd[i];
        if (fdholder != NULL && (fdholder->flags & (NDNR_FACE_UNDECIDED|NDNR_FACE_PASSIVE)) == 0) {
            ndn_charbuf_putf(b, " <tr>");
            ndn_charbuf_putf(b, "<td><b>fdholder:</b> %u</td>\t",
                             fdholder->filedesc);
            ndn_charbuf_putf(b, "<td>%6u / %u</td>\t\t",
                                 ndnr_meter_rate(h, fdholder->meter[FM_BYTI]),
                                 ndnr_meter_rate(h, fdholder->meter[FM_BYTO]));
            ndn_charbuf_putf(b, "<td>%9u / %u</td>\t\t",
                                 ndnr_meter_rate(h, fdholder->meter[FM_DATI]),
                                 ndnr_meter_rate(h, fdholder->meter[FM_INTO]));
            ndn_charbuf_putf(b, "<td>%9u / %u</td>",
                                 ndnr_meter_rate(h, fdholder->meter[FM_DATO]),
                                 ndnr_meter_rate(h, fdholder->meter[FM_INTI]));
            ndn_charbuf_putf(b, "</tr>" NL);
        }
    }
    ndn_charbuf_putf(b, "</tbody>");
    ndn_charbuf_putf(b, "</table>");
}

static void
collect_forwarding_html(struct ndnr_handle *h, struct ndn_charbuf *b)
{
    struct hashtb_enumerator ee;
    struct hashtb_enumerator *e = &ee;
    struct ndn_forwarding *f;
    int res;
    struct ndn_charbuf *name = ndn_charbuf_create();
    
    ndn_charbuf_putf(b, "<h4>Forwarding</h4>" NL);
    ndn_charbuf_putf(b, "<ul>");
    hashtb_start(h->nameprefix_tab, e);
    for (; e->data != NULL; hashtb_next(e)) {
        struct nameprefix_entry *ipe = e->data;
        ndn_name_init(name);
        res = ndn_name_append_components(name, e->key, 0, e->keysize);
        if (res < 0)
            abort();
        if (0) {
            ndn_charbuf_putf(b, " <li>");
            ndn_uri_append(b, name->buf, name->length, 1);
            ndn_charbuf_putf(b, "</li>" NL);
        }
        for (f = ipe->forwarding; f != NULL; f = f->next) {
            if ((f->flags & (NDN_FORW_ACTIVE | NDN_FORW_PFXO)) != 0) {
                ndn_name_init(name);
                res = ndn_name_append_components(name, e->key, 0, e->keysize);
                ndn_charbuf_putf(b, " <li>");
                ndn_uri_append(b, name->buf, name->length, 1);
                ndn_charbuf_putf(b,
                                 " <b>fdholder:</b> %u"
                                 " <b>flags:</b> 0x%x"
                                 " <b>expires:</b> %d",
                                 f->filedesc,
                                 f->flags & NDN_FORW_PUBMASK,
                                 f->expires);
                ndn_charbuf_putf(b, "</li>" NL);
            }
        }
    }
    hashtb_end(e);
    ndn_charbuf_destroy(&name);
    ndn_charbuf_putf(b, "</ul>");
}

static unsigned
ndnr_colorhash(struct ndnr_handle *h)
{
    unsigned const char *a = h->ndnr_id;
    unsigned v;
    
    v = (a[0] << 16) + (a[1] << 8) + a[2];
    return (v | 0xC0C0C0);
}

static struct ndn_charbuf *
collect_stats_html(struct ndnr_handle *h)
{
    struct ndnr_stats stats = {0};
    struct ndn_charbuf *b = ndn_charbuf_create();
    int pid;
    struct utsname un;
    
    uname(&un);
    pid = getpid();
    
    ndnr_collect_stats(h, &stats);
    ndn_charbuf_putf(b,
        "<html xmlns='http://www.w3.org/1999/xhtml'>"
        "<head>"
        "<title>%s ndnr[%d]</title>"
        //"<meta http-equiv='refresh' content='3'>"
        "<style type='text/css'>"
        "/*<![CDATA[*/"
        "p.header {color: white; background-color: blue; width: 100%%} "
        "table.tbl {border-style: solid; border-width: 1.0px 1.0px 1.0px 1.0px; border-color: black} "
        "td {border-style: solid; "
            "border-width: 1.0px 1.0px 1.0px 1.0px; "
            "border-color: #808080 #808080 #808080 #808080; "
            "padding: 6px 6px 6px 6px; "
            "margin-left: auto; margin-right: auto; "
            "text-align: center"
            "} "
        "td.left {text-align: left} "
        "/*]]>*/"
        "</style>"
        "</head>" NL
        "<body bgcolor='#%06X'>"
        "<p class='header'>%s ndnr[%d] local port %s api %d start %ld.%06u now %ld.%06u</p>" NL
        "<div><b>Content items:</b> %llu accessioned,"
        " %llu cached, %lu stale, %d sparse, %lu duplicate, %lu sent</div>" NL
        "<div><b>Interests:</b> %d names,"
        " %ld pending, %ld propagating, %ld noted</div>" NL
        "<div><b>Interest totals:</b> %lu accepted,"
        " %lu dropped, %lu sent, %lu stuffed</div>" NL,
        un.nodename,
        pid,
        ndnr_colorhash(h),
        un.nodename,
        pid,
        h->portstr,
        (int)NDN_API_VERSION,
        h->starttime, h->starttime_usec,
        h->sec,
        h->usec,
        (unsigned long long)hashtb_n(h->content_by_accession_tab), // XXXXXX - 
        (unsigned long long)(h->cob_count),
        h->n_stale,
        hashtb_n(h->content_by_accession_tab),
        h->content_dups_recvd,
        h->content_items_sent,
        hashtb_n(h->nameprefix_tab), stats.total_interest_counts,
        hashtb_n(h->propagating_tab) - stats.total_flood_control,
        stats.total_flood_control,
        h->interests_accepted, h->interests_dropped,
        h->interests_sent, h->interests_stuffed);
    collect_faces_html(h, b);
    collect_face_meter_html(h, b);
    collect_forwarding_html(h, b);
    ndn_charbuf_putf(b,
        "</body>"
        "</html>" NL);
    return(b);
}

/* XML formatting */

static void
collect_meter_xml(struct ndnr_handle *h, struct ndn_charbuf *b, struct ndnr_meter *m)
{
    uintmax_t total;
    unsigned rate;
    
    if (m == NULL)
        return;
    total = ndnr_meter_total(m);
    rate = ndnr_meter_rate(h, m);
    ndn_charbuf_putf(b, "<%s><total>%ju</total><persec>%u</persec></%s>",
        m->what, total, rate, m->what);
}

static void
collect_faces_xml(struct ndnr_handle *h, struct ndn_charbuf *b)
{
    int i;
    int m;
    struct ndn_charbuf *nodebuf;
    
    nodebuf = ndn_charbuf_create();
    ndn_charbuf_putf(b, "<faces>");
    for (i = 0; i < h->face_limit; i++) {
        struct fdholder *fdholder = h->fdholder_by_fd[i];
        if (fdholder != NULL && (fdholder->flags & NDNR_FACE_UNDECIDED) == 0) {
            ndn_charbuf_putf(b, "<fdholder>");
            ndn_charbuf_putf(b,
                             "<filedesc>%u</filedesc>"
                             "<faceflags>%04x</faceflags>",
                             fdholder->filedesc, fdholder->flags);
            ndn_charbuf_putf(b, "<pending>%d</pending>",
                             fdholder->pending_interests);
            ndn_charbuf_putf(b, "<recvcount>%d</recvcount>",
                             fdholder->recvcount);
            nodebuf->length = 0;
#if 0
            port = 0;
// XXX - fix this to know about fdholder->name
            int port = ndn_charbuf_append_sockaddr(nodebuf, fdholder->addr);
            if (port > 0) {
                const char *node = ndn_charbuf_as_string(nodebuf);
                ndn_charbuf_putf(b, "<ip>%s:%d</ip>", node, port);
            }
            if (fdholder->sendface != fdholder->filedesc &&
                fdholder->sendface != NDN_NOFACEID)
                ndn_charbuf_putf(b, "<via>%u</via>", fdholder->sendface);
#endif
            if (fdholder != NULL && (fdholder->flags & NDNR_FACE_PASSIVE) == 0) {
                ndn_charbuf_putf(b, "<meters>");
                for (m = 0; m < NDNR_FACE_METER_N; m++)
                    collect_meter_xml(h, b, fdholder->meter[m]);
                ndn_charbuf_putf(b, "</meters>");
            }
            ndn_charbuf_putf(b, "</fdholder>" NL);
        }
    }
    ndn_charbuf_putf(b, "</faces>");
    ndn_charbuf_destroy(&nodebuf);
}

static void
collect_forwarding_xml(struct ndnr_handle *h, struct ndn_charbuf *b)
{
    struct hashtb_enumerator ee;
    struct hashtb_enumerator *e = &ee;
    struct ndn_forwarding *f;
    int res;
    struct ndn_charbuf *name = ndn_charbuf_create();
    
    ndn_charbuf_putf(b, "<forwarding>");
    hashtb_start(h->nameprefix_tab, e);
    for (; e->data != NULL; hashtb_next(e)) {
        struct nameprefix_entry *ipe = e->data;
        for (f = ipe->forwarding, res = 0; f != NULL && !res; f = f->next) {
            if ((f->flags & (NDN_FORW_ACTIVE | NDN_FORW_PFXO)) != 0)
                res = 1;
        }
        if (res) {
            ndn_name_init(name);
            res = ndn_name_append_components(name, e->key, 0, e->keysize);
            ndn_charbuf_putf(b, "<fentry>");
            ndn_charbuf_putf(b, "<prefix>");
            ndn_uri_append(b, name->buf, name->length, 1);
            ndn_charbuf_putf(b, "</prefix>");
            for (f = ipe->forwarding; f != NULL; f = f->next) {
                if ((f->flags & (NDN_FORW_ACTIVE | NDN_FORW_PFXO)) != 0) {
                    ndn_charbuf_putf(b,
                                     "<dest>"
                                     "<filedesc>%u</filedesc>"
                                     "<flags>%x</flags>"
                                     "<expires>%d</expires>"
                                     "</dest>",
                                     f->filedesc,
                                     f->flags & NDN_FORW_PUBMASK,
                                     f->expires);
                }
            }
            ndn_charbuf_putf(b, "</fentry>");
        }
    }
    hashtb_end(e);
    ndn_charbuf_destroy(&name);
    ndn_charbuf_putf(b, "</forwarding>");
}

static struct ndn_charbuf *
collect_stats_xml(struct ndnr_handle *h)
{
    struct ndnr_stats stats = {0};
    struct ndn_charbuf *b = ndn_charbuf_create();
    int i;
        
    ndnr_collect_stats(h, &stats);
    ndn_charbuf_putf(b,
        "<ndnr>"
        "<identity>"
        "<ndnrid>");
    for (i = 0; i < sizeof(h->ndnr_id); i++)
        ndn_charbuf_putf(b, "%02X", h->ndnr_id[i]);
    ndn_charbuf_putf(b, "</ndnrid>"
        "<apiversion>%d</apiversion>"
        "<starttime>%ld.%06u</starttime>"
        "<now>%ld.%06u</now>"
        "</identity>",
        (int)NDN_API_VERSION,
        h->starttime, h->starttime_usec,
        h->sec,
        h->usec);
    ndn_charbuf_putf(b,
        "<cobs>"
        "<accessioned>%llu</accessioned>"
        "<cached>%llu</cached>"
        "<stale>%lu</stale>"
        "<sparse>%d</sparse>"
        "<duplicate>%lu</duplicate>"
        "<sent>%lu</sent>"
        "</cobs>"
        "<interests>"
        "<names>%d</names>"
        "<pending>%ld</pending>"
        "<propagating>%ld</propagating>"
        "<noted>%ld</noted>"
        "<accepted>%lu</accepted>"
        "<dropped>%lu</dropped>"
        "<sent>%lu</sent>"
        "<stuffed>%lu</stuffed>"
        "</interests>"
        "<lookups>"
        "<rightmost>"
        "<found>%lu</found>"
        "<iterations>%lu</iterations>"
        "<notfound>%lu</notfound>"
        "<iterations>%lu</iterations>"
        "</rightmost>"
        "<leftmost>"
        "<found>%lu</found>"
        "<iterations>%lu</iterations>"
        "<notfound>%lu</notfound>"
        "<iterations>%lu</iterations>"
        "</leftmost>"
        "</lookups>"
        ,
        (unsigned long long)hashtb_n(h->content_by_accession_tab), // XXXXXX -
        (unsigned long long)(h->cob_count),
        h->n_stale,
        hashtb_n(h->content_by_accession_tab),
        h->content_dups_recvd,
        h->content_items_sent,
        hashtb_n(h->nameprefix_tab), stats.total_interest_counts,
        hashtb_n(h->propagating_tab) - stats.total_flood_control,
        stats.total_flood_control,
        h->interests_accepted, h->interests_dropped,
        h->interests_sent, h->interests_stuffed,
        h->count_lmc_found, 
        h->count_lmc_found_iters,
        h->count_lmc_notfound,
        h->count_lmc_notfound_iters,
        h->count_rmc_found, 
        h->count_rmc_found_iters,
        h->count_rmc_notfound,
        h->count_rmc_notfound_iters
        );
    collect_faces_xml(h, b);
    collect_forwarding_xml(h, b);
    ndn_charbuf_putf(b, "</ndnr>" NL);
    return(b);
}

/**
 * create and initialize separately allocated meter.
 */
struct ndnr_meter *
ndnr_meter_create(struct ndnr_handle *h, const char *what)
{
    struct ndnr_meter *m;
    m = calloc(1, sizeof(*m));
    if (m == NULL)
        return(NULL);
    ndnr_meter_init(h, m, what);
    return(m);
}

/**
 * Destroy a separately allocated meter.
 */
void
ndnr_meter_destroy(struct ndnr_meter **pm)
{
    if (*pm != NULL) {
        free(*pm);
        *pm = NULL;
    }
}

/**
 * Initialize a meter.
 */
void
ndnr_meter_init(struct ndnr_handle *h, struct ndnr_meter *m, const char *what)
{
    if (m == NULL)
        return;
    memset(m, 0, sizeof(*m));
    if (what != NULL)
        strncpy(m->what, what, sizeof(m->what)-1);
    ndnr_meter_bump(h, m, 0);
}

static const unsigned meterHz = 7; /* 1/ln(8/7) would give RC const of 1 sec */

/**
 * Count something (messages, packets, bytes), and roll up some kind of
 * statistics on it.
 */
void
ndnr_meter_bump(struct ndnr_handle *h, struct ndnr_meter *m, unsigned amt)
{
    unsigned now; /* my ticks, wrap OK */
    unsigned t;
    unsigned r;
    if (m == NULL)
        return;
    now = (((unsigned)(h->sec)) * meterHz) + (h->usec * meterHz / 1000000U);
    t = m->lastupdate;
    m->total += amt;
    if (now - t > 166U)
        m->rate = amt; /* history has decayed away */
    else {
        /* Decay the old rate exponentially based on time since last sample. */
        for (r = m->rate; t != now && r != 0; t++)
            r = r - ((r + 7U) / 8U); /* multiply by 7/8, truncating */
        m->rate = r + amt;
    }
    m->lastupdate = now;
}

/**
 * Return the average rate (units per second) of a metered quantity.
 *
 * m may be NULL.
 */
unsigned
ndnr_meter_rate(struct ndnr_handle *h, struct ndnr_meter *m)
{
    unsigned denom = 8;
    if (m == NULL)
        return(0);
    ndnr_meter_bump(h, m, 0);
    if (m->rate > 0x0FFFFFFF)
        return(m->rate / denom * meterHz);
    return ((m->rate * meterHz + (denom - 1)) / denom);
}

/**
 * Return the grand total for a metered quantity.
 *
 * m may be NULL.
 */
uintmax_t
ndnr_meter_total(struct ndnr_meter *m)
{
    if (m == NULL)
        return(0);
    return (m->total);
}
