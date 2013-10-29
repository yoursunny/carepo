/**
 * @file ndnr_forwarding.c
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
#include "ndnr_forwarding.h"

#include "ndnr_io.h"
#include "ndnr_link.h"
#include "ndnr_match.h"
#include "ndnr_msg.h"
#include "ndnr_stats.h"
#include "ndnr_util.h"

PUBLIC void
r_fwd_finalize_nameprefix(struct hashtb_enumerator *e)
{
    struct ndnr_handle *h = hashtb_get_param(e->ht, NULL);
    struct nameprefix_entry *npe = e->data;
    struct propagating_entry *head = &npe->pe_head;
    if (head->next != NULL) {
        while (head->next != head)
            r_match_consume_interest(h, head->next);
    }
    ndn_indexbuf_destroy(&npe->forward_to);
    ndn_indexbuf_destroy(&npe->tap);
    while (npe->forwarding != NULL) {
        struct ndn_forwarding *f = npe->forwarding;
        npe->forwarding = f->next;
        free(f);
    }
}
