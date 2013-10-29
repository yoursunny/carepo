/**
 * @file ndnr_init.c
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
#include <inttypes.h>
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
#include <sys/mman.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

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
#include <sync/sync_plumbing.h>
#include <sync/SyncActions.h>

#include "ndnr_private.h"

#include "ndnr_init.h"

#include "ndnr_dispatch.h"
#include "ndnr_forwarding.h"
#include "ndnr_internal_client.h"
#include "ndnr_io.h"
#include "ndnr_msg.h"
#include "ndnr_net.h"
#include "ndnr_proto.h"
#include "ndnr_sendq.h"
#include "ndnr_store.h"
#include "ndnr_sync.h"
#include "ndnr_util.h"

static int load_policy(struct ndnr_handle *h);
static int merge_files(struct ndnr_handle *h);

static struct sync_plumbing_client_methods sync_client_methods = {
    .r_sync_msg = &r_sync_msg,
    .r_sync_fence = &r_sync_fence,
    .r_sync_enumerate = &r_sync_enumerate,
    .r_sync_lookup = &r_sync_lookup,
    .r_sync_local_store = &r_sync_local_store,
    .r_sync_upcall_store = &r_sync_upcall_store
};


/**
 * Read the contents of the repository config file
 *
 * Calls r_init_fail and returns NULL in case of error.
 * @returns unparsed content of config file in a newly allocated charbuf
 */
struct ndn_charbuf *
r_init_read_config(struct ndnr_handle *h)
{
    struct ndn_charbuf *path = NULL;
    struct ndn_charbuf *contents = NULL;
    size_t sz = 800;
    ssize_t sres = -1;
    int fd;
    
    h->directory = getenv("NDNR_DIRECTORY");
    if (h->directory == NULL || h->directory[0] == 0)
        h->directory = ".";
    path = ndn_charbuf_create();
    contents = ndn_charbuf_create();
    if (path == NULL || contents == NULL)
        return(NULL);
    ndn_charbuf_putf(path, "%s/config", h->directory);
    fd = open(ndn_charbuf_as_string(path), O_RDONLY);
    if (fd == -1) {
        if (errno == ENOENT)
            sres = 0;
        else
            r_init_fail(h, __LINE__, ndn_charbuf_as_string(path), errno);
    }
    else {
        for (;;) {
            sres = read(fd, ndn_charbuf_reserve(contents, sz), sz);
            if (sres == 0)
                break;
            if (sres < 0) {
                r_init_fail(h, __LINE__, "Read failed reading config", errno);
                break;
            }
            contents->length += sres;
            if (contents->length > 999999) {
                r_init_fail(h, __LINE__, "config file too large", 0);
                sres = -1;
                break;
            }
        }
        close(fd);
    }
    ndn_charbuf_destroy(&path);
    if (sres < 0)
        ndn_charbuf_destroy(&contents);
    return(contents);
}

static int
r_init_debug_getenv(struct ndnr_handle *h, const char *envname)
{
    const char *debugstr;
    int debugval;
    
    debugstr = getenv(envname);
    debugval = ndnr_msg_level_from_string(debugstr);
    /* Treat 1 and negative specially, for some backward compatibility. */
    if (debugval == 1)
        debugval = NDNL_WARNING;
    if (debugval < 0) {
        debugval = NDNL_FINEST;
        if (h != NULL)
            ndnr_msg(h, "%s='%s' is not valid, using FINEST", envname, debugstr);
    }
    return(debugval);
}

/**
 * Get the specified numerical config value, subject to limits.
 */
intmax_t
r_init_confval(struct ndnr_handle *h, const char *key,
                     intmax_t lo, intmax_t hi, intmax_t deflt) {
    const char *s;
    intmax_t v;
    char *ep;
    
    if (!(lo <= deflt && deflt <= hi))
        abort();
    s = getenv(key);
    if (s != NULL && s[0] != 0) {
        ep = "x";
        v = strtoimax(s, &ep, 10);
        if (v != 0 || ep[0] == 0) {
            if (v > hi)
                v = hi;
            if (v < lo)
                v = lo;
            if (NDNSHOULDLOG(h, mmm, NDNL_FINEST))
                ndnr_msg(h, "Using %s=%jd", key, v);
            return(v);
        }
    }
    return (deflt);
}

#define NDNR_CONFIG_PASSMASK   0x003 /* config pass */
#define NDNR_CONFIG_IGNORELINE 0x100 /* Set if there are prior problems */
#define NDNR_CONFIG_ERR        0x200 /* Report error rather than warning */
/**
 * Message helper for r_init_parse_config()
 */
static void
r_init_config_msg(struct ndnr_handle *h, int flags,
                  int line, int chindex, const char *msg)
{
    const char *problem = "Problem";
    int log_at = NDNL_WARNING;
    
    log_at = NDNL_WARNING;
    if ((flags & NDNR_CONFIG_ERR) != 0) {
        problem = "Error";
        log_at = NDNL_ERROR;
    }
    if ((flags & (NDNR_CONFIG_IGNORELINE|NDNR_CONFIG_PASSMASK)) == 1 &&
        NDNSHOULDLOG(h, mmm, log_at)) {
        ndnr_msg(h, "%s in config file %s/config - line %d column %d: %s",
                 problem, h->directory, line, chindex + 1, msg);
    }
}

/**
 * Parse the buffered configuration found in config
 *
 * The pass argument controls what is done with the result:
 *   0 - silent check for syntax errors;
 *   1 - check for syntax errors and warnings, logging the results,
 *   2 - incorporate settings into environ.
 *
 * @returns -1 if an error is found, otherwise the count of warnings.
 */
int
r_init_parse_config(struct ndnr_handle *h, struct ndn_charbuf *config, int pass)
{
    struct ndn_charbuf *key = NULL;
    struct ndn_charbuf *value = NULL;
    const unsigned char *b;
    int line;
    size_t i;
    size_t sol; /* start of line */
    size_t len; /* config->len */
    size_t ndx; /* temp for column report*/
    int ch;
    int warns = 0;
    int errors = 0;
    int use_it = 0;
    static const char pclegal[] = 
        "~@%-+=:,./[]"
        "abcdefghijklmnopqrstuvwxyz"
        "0123456789"
        "_"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const char *klegal = strchr(pclegal, 'a');
    int flags; /* for reporting */
    
    b = config->buf;
    len = config->length;
    if (len == 0)
        return(0);
    ndn_charbuf_as_string(config);
    key = ndn_charbuf_create();
    value = ndn_charbuf_create();
    if (key == NULL || value == NULL)
        return(-1);
    /* Ensure there is null termination in the buffered config */
    if (ndn_charbuf_as_string(config) == NULL)
        return(-1);
    for (line = 1, i = 0, ch = b[0], sol = 0; i < len;) {
        flags = pass;
        use_it = 0;
        if (ch > ' ' && ch != '#') {
            key->length = value->length = 0;
            /* parse key */
            while (i < len && ch != '\n' && ch != '=') {
                ndn_charbuf_append_value(key, ch, 1);
                ch = b[++i];
            }
            if (ch == '=')
                ch = b[++i];
            else {
                r_init_config_msg(h, flags, line, key->length, "missing '='");
                flags |= NDNR_CONFIG_IGNORELINE;
                warns++;
                ch = '\n';
            }
            /* parse value */
            while (i < len && ch > ' ') {
                ndn_charbuf_append_value(value, ch, 1);
                ch = b[++i];
            }
            /* See if it might be one of ours */
            if (key->length < 5 || (memcmp(key->buf, "NDNR_", 5) != 0 &&
                                    memcmp(key->buf, "NDNS_", 5) != 0)) {
                r_init_config_msg(h, flags, line, 0,
                                  "ignoring unrecognized key");
                flags |= NDNR_CONFIG_IGNORELINE;
                warns++;
                use_it = 0;
            }
            else
                use_it = 1;

            /* Check charset of key */
            ndx = strspn(ndn_charbuf_as_string(key), klegal);
            if (ndx != key->length) {
                errors += use_it;
                r_init_config_msg(h, (flags | NDNR_CONFIG_ERR), line, ndx,
                                  "unexpected character in key");
                flags |= NDNR_CONFIG_IGNORELINE;
                warns++;
            }
            /* Check charset of value */
            ndx = strspn(ndn_charbuf_as_string(value), pclegal);
            if (ndx != value->length) {
                errors += use_it;
                r_init_config_msg(h, (flags | NDNR_CONFIG_ERR),
                                  line, key->length + 1 + ndx,
                                  "unexpected character in value");
                flags |= NDNR_CONFIG_IGNORELINE;
                warns++;
            }
        }
        if (ch == '#') {
            /* a comment line or error recovery. */
            while (i < len && ch != '\n')
                ch = b[++i];
        }
        while (i < len && ch <= ' ') {
            if (ch == '\n') {
                line++;
                sol = i;
                break;
            }
            if (memchr("\r\t ", ch, 3) == NULL) {
                r_init_config_msg(h, pass, line, i - sol,
                                  "non-whitespace control char at end of line");
                warns++;
            } 
            ch = b[++i];
        }
        if (i == len) {
            r_init_config_msg(h, flags, line, i - sol,
                              "missing newline at end of file");
            warns++;
            ch = '\n';
        }
        else if (ch == '\n')
            ch = b[++i];
        else {
            r_init_config_msg(h, flags, line, i - sol, "junk at end of line");
            flags |= NDNR_CONFIG_IGNORELINE;
            warns++;
            ch = '#';
        }
        if (flags == 0 && strcmp(ndn_charbuf_as_string(key), "NDNR_DEBUG") == 0) {
            /* Set this on pass 0 so that it takes effect sooner. */
            h->debug = 1;
            setenv("NDNR_DEBUG", ndn_charbuf_as_string(value), 1);
            h->debug = r_init_debug_getenv(h, "NDNR_DEBUG");
        }
        if (pass == 2 && use_it) {
            if (NDNSHOULDLOG(h, mmm, NDNL_FINEST))
                ndnr_msg(h, "config: %s=%s",
                        ndn_charbuf_as_string(key),
                        ndn_charbuf_as_string(value));
            setenv(ndn_charbuf_as_string(key), ndn_charbuf_as_string(value), 1);
        }
    }
    ndn_charbuf_destroy(&key);
    ndn_charbuf_destroy(&value);
    return(errors ? -1 : warns);
}

static int
establish_min_send_bufsize(struct ndnr_handle *h, int fd, int minsize)
{
    int res;
    int bufsize;
    int obufsize;
    socklen_t bufsize_sz;

    bufsize_sz = sizeof(bufsize);
    res = getsockopt(fd, SOL_SOCKET, SO_SNDBUF, &bufsize, &bufsize_sz);
    if (res == -1)
        return (res);
    obufsize = bufsize;
    if (bufsize < minsize) {
        bufsize = minsize;
        res = setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &bufsize, sizeof(bufsize));
        if (res == -1)
            return(res);
    }
    if (NDNSHOULDLOG(h, sdfdsf, NDNL_INFO))
        ndnr_msg(h, "SO_SNDBUF for fd %d is %d (was %d)", fd, bufsize, obufsize);
    return(bufsize);
}

/**
 * If so configured, replace fd with a tcp socket
 * @returns new address family
 */
static int
try_tcp_instead(int fd)
{
    struct addrinfo hints = {0};
    struct addrinfo *ai = NULL;
    const char *port = NULL;
    const char *proto = NULL;
    int res;
    int sock;
    int ans = AF_UNIX;
    int yes = 1;
    
    proto = getenv("NDNR_PROTO");
    if (proto == NULL || strcasecmp(proto, "tcp") != 0)
        return(ans);
    port = getenv("NDN_LOCAL_PORT");
    if (port == NULL || port[0] == 0)
        port = "6363";
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = 0;
    hints.ai_protocol = 0;
    res = getaddrinfo(NULL, port, &hints, &ai);
    if (res == 0) {
        sock = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (sock != -1) {
            res = connect(sock, ai->ai_addr, ai->ai_addrlen);
            if (res == 0) {
                setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &yes, sizeof(yes));
                dup2(sock, fd);
                ans = ai->ai_family;
            }
            else
                close(sock);
        }
        freeaddrinfo(ai);
    }
    return(ans);
}

PUBLIC struct ndnr_parsed_policy *
ndnr_parsed_policy_create(void)
{
    struct ndnr_parsed_policy *pp;
    pp = calloc(1, sizeof(struct ndnr_parsed_policy));
    pp->store = ndn_charbuf_create();
    pp->namespaces = ndn_indexbuf_create();
    return(pp);
}

PUBLIC void
ndnr_parsed_policy_destroy(struct ndnr_parsed_policy **ppp)
{
    struct ndnr_parsed_policy *pp;
    
    if (*ppp == NULL)
        return;
    pp = *ppp;
    ndn_charbuf_destroy(&pp->store);
    ndn_indexbuf_destroy(&pp->namespaces);
    free(pp);
    *ppp = NULL;
}

/**
 * Create a new ndnr instance
 * @param progname - name of program binary, used for locating helpers
 * @param logger - logger function
 * @param loggerdata - data to pass to logger function
 */
PUBLIC struct ndnr_handle *
r_init_create(const char *progname, ndnr_logger logger, void *loggerdata)
{
    char *sockname = NULL;
    const char *portstr = NULL;
    const char *listen_on = NULL;
    const char *d = NULL;
    struct ndnr_handle *h = NULL;
    struct hashtb_param param = {0};
    struct ndn_charbuf *config = NULL;
    int res;
    
    h = calloc(1, sizeof(*h));
    if (h == NULL)
        return(h);
    h->notify_after = 0; //NDNR_MAX_ACCESSION;
    h->logger = logger;
    h->loggerdata = loggerdata;
    h->logpid = (int)getpid();
    h->progname = progname;
    h->debug = -1;
    config = r_init_read_config(h);
    if (config == NULL)
        goto Bail;
    r_init_parse_config(h, config, 0); /* silent pass to pick up NDNR_DEBUG */
    h->debug = 1; /* so that we see any complaints */
    h->debug = r_init_debug_getenv(h, "NDNR_DEBUG");
    res = r_init_parse_config(h, config, 1);
    if (res < 0) {
        h->running = -1;
        goto Bail;
    }
    r_init_parse_config(h, config, 2);
    sockname = r_net_get_local_sockname();
    h->skiplinks = ndn_indexbuf_create();
    h->face_limit = 10; /* soft limit */
    h->fdholder_by_fd = calloc(h->face_limit, sizeof(h->fdholder_by_fd[0]));
    param.finalize_data = h;
    param.finalize = &r_fwd_finalize_nameprefix;
    h->nameprefix_tab = hashtb_create(sizeof(struct nameprefix_entry), &param);
    param.finalize = 0; // PRUNED &r_fwd_finalize_propagating;
    h->propagating_tab = hashtb_create(sizeof(struct propagating_entry), &param);
    param.finalize = &r_proto_finalize_enum_state;
    h->enum_state_tab = hashtb_create(sizeof(struct enum_state), &param);
    h->min_stale = ~0;
    h->max_stale = 0;
    h->unsol = ndn_indexbuf_create();
    h->ticktock.descr[0] = 'C';
    h->ticktock.micros_per_base = 1000000;
    h->ticktock.gettime = &r_util_gettime;
    h->ticktock.data = h;
    h->sched = ndn_schedule_create(h, &h->ticktock);
    h->starttime = h->sec;
    h->starttime_usec = h->usec;
    h->oldformatcontentgrumble = 1;
    h->oldformatinterestgrumble = 1;
    h->cob_limit = 4201;
    h->start_write_scope_limit = r_init_confval(h, "NDNR_START_WRITE_SCOPE_LIMIT", 0, 3, 3);
    h->debug = 1; /* so that we see any complaints */
    h->debug = r_init_debug_getenv(h, "NDNR_DEBUG");
    h->syncdebug = r_init_debug_getenv(h, "NDNS_DEBUG");
    portstr = getenv("NDNR_STATUS_PORT");
    if (portstr == NULL || portstr[0] == 0 || strlen(portstr) > 10)
        portstr = "";
    h->portstr = portstr;
    ndnr_msg(h, "NDNR_DEBUG=%d NDNR_DIRECTORY=%s NDNR_STATUS_PORT=%s", h->debug, h->directory, h->portstr);
    listen_on = getenv("NDNR_LISTEN_ON");
    if (listen_on != NULL && listen_on[0] != 0)
        ndnr_msg(h, "NDNR_LISTEN_ON=%s", listen_on);
    
    if (ndnr_init_repo_keystore(h, NULL) < 0) {
        h->running = -1;
        goto Bail;
    }
    r_util_reseed(h);
    r_store_init(h);
    if (h->running == -1) goto Bail;
    while (h->active_in_fd >= 0) {
        r_dispatch_process_input(h, h->active_in_fd);
        r_store_trim(h, h->cob_limit);
        ndn_schedule_run(h->sched);
    }
    ndnr_msg(h, "Repository file is indexed");
    if (h->face0 == NULL) {
        struct fdholder *fdholder;
        fdholder = calloc(1, sizeof(*fdholder));
        if (dup2(open("/dev/null", O_RDONLY), 0) == -1)
            ndnr_msg(h, "stdin: %s", strerror(errno));
        fdholder->filedesc = 0;
        fdholder->flags = (NDNR_FACE_GG | NDNR_FACE_NORECV);
        r_io_enroll_face(h, fdholder);
    }
    ndnr_direct_client_start(h);
    d = getenv("NDNR_SKIP_VERIFY");
#if (NDN_API_VERSION >= 4004)
    if (d != NULL && strcmp(d, "1") == 0) {
        ndnr_msg(h, "NDNR_SKIP_VERIFY=%s", d);
        ndn_defer_verification(h->direct_client, 1);
    }
#endif
    if (ndn_connect(h->direct_client, NULL) != -1) {
        int af = 0;
        int bufsize;
        int flags;
        int fd;
        struct fdholder *fdholder;

        fd = ndn_get_connection_fd(h->direct_client);
        // Play a dirty trick here - if this wins, we can fix it right in the c lib later on...
        af = try_tcp_instead(fd);  
        flags = NDNR_FACE_NDND;
        if (af == AF_INET)
            flags |= NDNR_FACE_INET;
        else if (af == AF_INET6)
            flags |= NDNR_FACE_INET6;
        else
            flags |= NDNR_FACE_LOCAL;
        fdholder = r_io_record_fd(h, fd, "NDND", 5, flags);
        if (fdholder == NULL) abort();
        ndnr_uri_listen(h, h->direct_client, "ndn:/%C1.M.S.localhost/%C1.M.SRV/repository",
                        &ndnr_answer_req, OP_SERVICE);
        ndnr_uri_listen(h, h->direct_client, "ndn:/%C1.M.S.neighborhood/%C1.M.SRV/repository",
                        &ndnr_answer_req, OP_SERVICE);
        bufsize = r_init_confval(h, "NDNR_MIN_SEND_BUFSIZE", 1, 2097152, 16384);
        establish_min_send_bufsize(h, fd, bufsize);
    }
    else
        ndn_disconnect(h->direct_client); // Apparently ndn_connect error case needs work.
    if (1 == r_init_confval(h, "NDNS_ENABLE", 0, 1, 1)) {
        h->sync_plumbing = calloc(1, sizeof(struct sync_plumbing));
        h->sync_plumbing->ndn = h->direct_client;
        h->sync_plumbing->sched = h->sched;
        h->sync_plumbing->client_methods = &sync_client_methods;
        h->sync_plumbing->client_data = h;
        h->sync_base = SyncNewBaseForActions(h->sync_plumbing);
    }
    if (-1 == load_policy(h))
        goto Bail;
    r_net_listen_on(h, listen_on);
    ndnr_internal_client_start(h);
    r_proto_init(h);
    r_proto_activate_policy(h, h->parsed_policy);
    if (merge_files(h) == -1)
        r_init_fail(h, __LINE__, "Unable to merge additional repository data files.", errno);
    if (h->running == -1) goto Bail;
    if (h->sync_plumbing) {
        // Start sync running
        // returns < 0 if a failure occurred
        // returns 0 if the name updates should fully restart
        // returns > 0 if the name updates should restart at last fence
        res = h->sync_plumbing->sync_methods->sync_start(h->sync_plumbing, NULL);
        if (res < 0) {
            r_init_fail(h, __LINE__, "starting sync", res);
            abort();
        }
        else if (res > 0) {
            // XXX: need to work out details of starting from last fence.
            // By examination of code, SyncActions won't take this path
        }
    }
Bail:
    if (sockname)
        free(sockname);
    sockname = NULL;
    ndn_charbuf_destroy(&config);
    if (h->running == -1)
        r_init_destroy(&h);
    return(h);
}

void
r_init_fail(struct ndnr_handle *ndnr, int line, const char *culprit, int err)
{
    if (err > 0)
        ndnr_msg(ndnr, "Startup failure %d %s - %s", line, culprit,
                 strerror(err));
    else {
        ndnr_msg(ndnr, "Startup failure %d %s - error %d", line, culprit, err);
    }
    ndnr->running = -1;
}

/**
 * Destroy the ndnr instance, releasing all associated resources.
 */
PUBLIC void
r_init_destroy(struct ndnr_handle **pndnr)
{
    struct ndnr_handle *h = *pndnr;
    int stable;
    if (h == NULL)
        return;
    stable = h->active_in_fd == -1 ? 1 : 0;
    r_io_shutdown_all(h);
    ndnr_direct_client_stop(h);
    ndn_schedule_destroy(&h->sched);
    hashtb_destroy(&h->propagating_tab);
    hashtb_destroy(&h->nameprefix_tab);
    hashtb_destroy(&h->enum_state_tab);
    hashtb_destroy(&h->content_by_accession_tab);

    // SyncActions sync_stop method should be shutting down heartbeat
    if (h->sync_plumbing) {
        h->sync_plumbing->sync_methods->sync_stop(h->sync_plumbing, NULL);
        free(h->sync_plumbing);
        h->sync_plumbing = NULL;
        h->sync_base = NULL; // freed by sync_stop ?
    }
    
    r_store_final(h, stable);
    
    if (h->fds != NULL) {
        free(h->fds);
        h->fds = NULL;
        h->nfds = 0;
    }
    if (h->fdholder_by_fd != NULL) {
        free(h->fdholder_by_fd);
        h->fdholder_by_fd = NULL;
        h->face_limit = h->face_gen = 0;
    }
    if (h->content_by_cookie != NULL) {
        free(h->content_by_cookie);
        h->content_by_cookie = NULL;
        h->cookie_limit = 1;
    }
    ndn_charbuf_destroy(&h->scratch_charbuf);
    ndn_indexbuf_destroy(&h->skiplinks);
    ndn_indexbuf_destroy(&h->scratch_indexbuf);
    ndn_indexbuf_destroy(&h->unsol);
    if (h->parsed_policy != NULL) {
        ndn_indexbuf_destroy(&h->parsed_policy->namespaces);
        ndn_charbuf_destroy(&h->parsed_policy->store);
        free(h->parsed_policy);
        h->parsed_policy = NULL;
    }
    ndn_charbuf_destroy(&h->policy_name);
    ndn_charbuf_destroy(&h->policy_link_cob);
    ndn_charbuf_destroy(&h->ndnr_keyid);
    free(h);
    *pndnr = NULL;
}

int
r_init_map_and_process_file(struct ndnr_handle *h, struct ndn_charbuf *filename, int add_content)
{
    int res = 0;
    int dres;
    struct stat statbuf;
    unsigned char *mapped_file = MAP_FAILED;
    unsigned char *msg;
    size_t size;
    int fd = -1;
    struct content_entry *content;
    struct ndn_skeleton_decoder *d;
    struct fdholder *fdholder;
    
    fd = r_io_open_repo_data_file(h, ndn_charbuf_as_string(filename), 0);
    if (fd == -1)   // Normal exit
        return(1);
    
    res = fstat(fd, &statbuf);
    if (res != 0) {
        ndnr_msg(h, "stat failed for %s (fd=%d), %s (errno=%d)",
                 ndn_charbuf_as_string(filename), fd, strerror(errno), errno);
        res = -errno;
        goto Bail;
    }
    if (statbuf.st_size == 0)
        goto Bail;
    
    mapped_file = mmap(NULL, statbuf.st_size, PROT_READ, MAP_SHARED, fd, 0);
    if (mapped_file == MAP_FAILED) {
        ndnr_msg(h, "mmap failed for %s (fd=%d), %s (errno=%d)",
                 ndn_charbuf_as_string(filename), fd, strerror(errno), errno);
        res = -errno;
        goto Bail;
    }
    fdholder = r_io_fdholder_from_fd(h, fd);
    d = &fdholder->decoder;
    msg = mapped_file;
    size = statbuf.st_size;
    while (d->index < size) {
        dres = ndn_skeleton_decode(d, msg + d->index, size - d->index);
        if (!NDN_FINAL_DSTATE(d->state))
            break;
        if (add_content) {
            content = process_incoming_content(h, fdholder, msg + d->index - dres, dres, NULL);
            if (content != NULL)
                r_store_commit_content(h, content);
        }
    }
    
    if (d->index != size || !NDN_FINAL_DSTATE(d->state)) {
        ndnr_msg(h, "protocol error on fdholder %u (state %d), discarding %d bytes",
                 fdholder->filedesc, d->state, (int)(size - d->index));
        res = -1;
        goto Bail;
    }
    
Bail:
    if (mapped_file != MAP_FAILED)
        munmap(mapped_file, statbuf.st_size);
    r_io_shutdown_client_fd(h, fd);
    return (res);
}

static int
merge_files(struct ndnr_handle *h)
{
    int i, last_file;
    int res;
    struct ndn_charbuf *filename = ndn_charbuf_create();
    
    // first parse the file(s) making sure there are no errors
    for (i = 2;; i++) {
        filename->length = 0;
        ndn_charbuf_putf(filename, "repoFile%d", i);
        res = r_init_map_and_process_file(h, filename, 0);
        if (res == 1)
            break;
        if (res < 0) {
            ndnr_msg(h, "Error parsing repository file %s", ndn_charbuf_as_string(filename));
            return (-1);
        }
    }
    last_file = i - 1;
    
    for (i = 2; i <= last_file; i++) {
        filename->length = 0;
        ndn_charbuf_putf(filename, "repoFile%d", i);
        res = r_init_map_and_process_file(h, filename, 1);
        if (res < 0) {
            ndnr_msg(h, "Error in phase 2 incorporating repository file %s", ndn_charbuf_as_string(filename));
            return (-1);
        }
    }
    
    for (i = last_file; i > 1; --i) {
        filename->length = 0;
        ndn_charbuf_putf(filename, "%s/repoFile%d", h->directory, i);
        if (NDNSHOULDLOG(h, LM_128, NDNL_INFO))
            ndnr_msg(h, "unlinking %s", ndn_charbuf_as_string(filename));   
        unlink(ndn_charbuf_as_string(filename));
    }
    ndn_charbuf_destroy(&filename);
    return (0);
}

static struct ndn_charbuf *
ndnr_init_policy_cob(struct ndnr_handle *ndnr, struct ndn *h,
                     struct ndn_charbuf *basename,
                     int freshness, struct ndn_charbuf *content)
{
    struct ndn_signing_params sp = NDN_SIGNING_PARAMS_INIT;
    struct ndn_charbuf *name = ndn_charbuf_create();
    struct ndn_charbuf *pubid = ndn_charbuf_create();
    struct ndn_charbuf *pubkey = ndn_charbuf_create();
    struct ndn_charbuf *keyid = ndn_charbuf_create();
    struct ndn_charbuf *tcob = ndn_charbuf_create();
    struct ndn_charbuf *cob = NULL;          // result
    int res;
    
    res = ndn_get_public_key(h, NULL, pubid, pubkey);
    if (res < 0) 
        goto Leave;
    res = ndn_charbuf_append_charbuf(name, basename);
    if (ndn_name_from_uri(name, "%00") < 0)
        goto Leave;
    sp.sp_flags |= NDN_SP_FINAL_BLOCK;
    sp.type = NDN_CONTENT_DATA;
    sp.freshness = freshness;
    res |= ndn_sign_content(h, tcob, name, &sp, content->buf, content->length);
    if (res == 0) {
        cob = tcob;
        tcob = NULL;
    }
    
Leave:
    ndn_charbuf_destroy(&name);
    ndn_charbuf_destroy(&pubid);
    ndn_charbuf_destroy(&pubkey);
    ndn_charbuf_destroy(&keyid);
    ndn_charbuf_destroy(&tcob);
    return (cob);
}
/**
 * should probably return a new cob, rather than reusing one.
 * should publish link as:
 *    NDNRID_POLICY_URI("ndn:/%C1.M.S.localhost/%C1.M.SRV/repository/POLICY)/%C1.M.K--pubid--/--version--/%00
 * should have key locator which is the key name of the repository
 */
PUBLIC struct ndn_charbuf *
ndnr_init_policy_link_cob(struct ndnr_handle *ndnr, struct ndn *h,
                          struct ndn_charbuf *targetname)
{
    struct ndn_signing_params sp = NDN_SIGNING_PARAMS_INIT;
    struct ndn_charbuf *name = ndn_charbuf_create();
    struct ndn_charbuf *pubid = ndn_charbuf_create();
    struct ndn_charbuf *pubkey = ndn_charbuf_create();
    struct ndn_charbuf *keyid = ndn_charbuf_create();
    struct ndn_charbuf *content = ndn_charbuf_create();
    struct ndn_charbuf *cob = ndn_charbuf_create();
    struct ndn_charbuf *answer = NULL;
    int res;
    
    res = ndn_get_public_key(h, NULL, pubid, pubkey);
    if (res < 0)
        goto Bail;
    if (ndn_name_from_uri(name, NDNRID_POLICY_URI) < 0)
        goto Bail;
    res |= ndn_charbuf_append_value(keyid, NDN_MARKER_CONTROL, 1);
    res |= ndn_charbuf_append_string(keyid, ".M.K");
    res |= ndn_charbuf_append_value(keyid, 0, 1);
    res |= ndn_charbuf_append_charbuf(keyid, pubid);
    res |= ndn_name_append(name, keyid->buf, keyid->length);
    res |= ndn_create_version(h, name, NDN_V_NOW, 0, 0);
    if (ndn_name_from_uri(name, "%00") < 0)
        goto Bail;
    sp.sp_flags |= NDN_SP_FINAL_BLOCK;
    sp.type = NDN_CONTENT_LINK;
    res |= ndnb_append_Link(content, targetname, "Repository Policy", NULL);
    if (res != 0)
        goto Bail;
    res |= ndn_sign_content(h, cob, name, &sp, content->buf, content->length);
    if (res != 0)
        goto Bail;
    answer = cob;
    cob = NULL;
    
Bail:
    ndn_charbuf_destroy(&name);
    ndn_charbuf_destroy(&pubid);
    ndn_charbuf_destroy(&pubkey);
    ndn_charbuf_destroy(&keyid);
    ndn_charbuf_destroy(&content);
    ndn_charbuf_destroy(&cob);
    return (answer);
}


/**
 * Load a link to the repo policy from the repoPolicy file and load the link
 * target to extract the actual policy.
 * If a policy file does not exist a new one is created, with a link to a policy
 * based either on the environment variable NDNR_GLOBAL_PREFIX or the system
 * default value of ndn:/named-data.net/ndn/Repos, plus the system defaults for
 * other fields.
 * This routine must be called after the btree code is initialized and capable
 * of returning content objects.
 * Sets the parsed_policy field of the handle to be the new policy.
 */
static int
load_policy(struct ndnr_handle *ndnr)
{
    int fd;
    ssize_t res;
    struct content_entry *content = NULL;
    const unsigned char *content_msg = NULL;
    struct ndn_parsed_ContentObject pco = {0};
    struct ndn_parsed_Link pl = {0};
    struct ndn_indexbuf *nc = NULL;
    struct ndn_charbuf *basename = NULL;
    struct ndn_charbuf *policy = NULL;
    struct ndn_charbuf *policy_cob = NULL;
    struct ndn_charbuf *policyFileName;
    const char *global_prefix;
    const unsigned char *buf = NULL;
    size_t length = 0;
    int segment = 0;
    int final = 0;
    struct ndn_buf_decoder decoder;
    struct ndn_buf_decoder *d;
    
    policyFileName = ndn_charbuf_create();
    ndn_charbuf_putf(policyFileName, "%s/repoPolicy", ndnr->directory);
    ndnr->parsed_policy = ndnr_parsed_policy_create();
    fd = open(ndn_charbuf_as_string(policyFileName), O_RDONLY);
    if (fd >= 0) {
        ndnr->policy_link_cob = ndn_charbuf_create();
        ndn_charbuf_reserve(ndnr->policy_link_cob, 4096);   // limits the size of the policy link
        ndnr->policy_link_cob->length = 0;    // clear the buffer
        res = read(fd, ndnr->policy_link_cob->buf, ndnr->policy_link_cob->limit - ndnr->policy_link_cob->length);
        close(fd);
        if (res == -1) {
            r_init_fail(ndnr, __LINE__, "Error reading repoPolicy file.", errno);
            ndn_charbuf_destroy(&ndnr->policy_link_cob);
            ndn_charbuf_destroy(&policyFileName);
            return(-1);
        }
        ndnr->policy_link_cob->length = res;
        nc = ndn_indexbuf_create();
        res = ndn_parse_ContentObject(ndnr->policy_link_cob->buf,
                                      ndnr->policy_link_cob->length, &pco, nc);
        res = ndn_ref_tagged_BLOB(NDN_DTAG_Content, ndnr->policy_link_cob->buf,
                                  pco.offset[NDN_PCO_B_Content],
                                  pco.offset[NDN_PCO_E_Content],
                                  &buf, &length);
        d = ndn_buf_decoder_start(&decoder, buf, length);
        res = ndn_parse_Link(d, &pl, NULL);
        if (res <= 0) {
            ndnr_msg(ndnr, "Policy link is malformed.");
            goto CreateNewPolicy;
        }
        basename = ndn_charbuf_create();
        ndn_charbuf_append(basename, buf + pl.offset[NDN_PL_B_Name],
                           pl.offset[NDN_PL_E_Name] - pl.offset[NDN_PL_B_Name]);
        ndnr->policy_name = ndn_charbuf_create(); // to detect writes to this name
        ndn_charbuf_append_charbuf(ndnr->policy_name, basename); // has version
        ndn_name_chop(ndnr->policy_name, NULL, -1); // get rid of version
        policy = ndn_charbuf_create();
        // if we fail to retrieve the link target, report and then create a new one
        do {
            ndn_name_append_numeric(basename, NDN_MARKER_SEQNUM, segment++);
            content = r_store_lookup_ndnb(ndnr, basename->buf, basename->length);
            if (content == NULL) {
                ndnr_debug_ndnb(ndnr, __LINE__, "policy lookup failed for", NULL,
                                basename->buf, basename->length);
                break;
            }
            ndn_name_chop(basename, NULL, -1);
            content_msg = r_store_content_base(ndnr, content);
            if (content_msg == NULL) {
                ndnr_debug_ndnb(ndnr, __LINE__, "Unable to read policy object", NULL,
                                basename->buf, basename->length);
                break;
            }
            res = ndn_parse_ContentObject(content_msg, r_store_content_size(ndnr, content), &pco, nc);
            res = ndn_ref_tagged_BLOB(NDN_DTAG_Content, content_msg,
                                      pco.offset[NDN_PCO_B_Content],
                                      pco.offset[NDN_PCO_E_Content],
                                      &buf, &length);
            ndn_charbuf_append(policy, buf, length);
            final = ndn_is_final_pco(content_msg, &pco, nc);
        } while (!final && segment < 100);
        if (policy->length == 0) {
            ndnr_msg(ndnr, "Policy link points to empty or non-existent policy.");
            goto CreateNewPolicy;
        }
        if (segment >= 100) {
            r_init_fail(ndnr, __LINE__, "Policy link points to policy with too many segments.", 0);
            return(-1);
        }
        if (r_proto_parse_policy(ndnr, policy->buf, policy->length, ndnr->parsed_policy) < 0) {
            ndnr_msg(ndnr, "Policy link points to malformed policy.");
            goto CreateNewPolicy;
        }
        res = ndn_name_comp_get(content_msg, nc, nc->n - 3, &buf, &length);
        if (length != 7 || buf[0] != NDN_MARKER_VERSION) {
            ndnr_msg(ndnr, "Policy link points to unversioned policy.");
            goto CreateNewPolicy;
        }
        memmove(ndnr->parsed_policy->version, buf, sizeof(ndnr->parsed_policy->version));
        ndn_indexbuf_destroy(&nc);
        ndn_charbuf_destroy(&basename);
        ndn_charbuf_destroy(&policy);
        ndn_charbuf_destroy(&policyFileName);
        return (0);
    }
    
CreateNewPolicy:
    // clean up if we had previously done some allocation
    ndn_indexbuf_destroy(&nc);
    ndn_charbuf_destroy(&basename);
    ndn_charbuf_destroy(&policy);
    ndn_charbuf_destroy(&ndnr->policy_name);
    ndnr_msg(ndnr, "Creating new policy file.");
    // construct the policy content object
    global_prefix = getenv ("NDNR_GLOBAL_PREFIX");
    if (global_prefix != NULL)
        ndnr_msg(ndnr, "NDNR_GLOBAL_PREFIX=%s", global_prefix);
    else 
        global_prefix = "ndn:/named-data.net/ndn/Repos";
    policy = ndn_charbuf_create();
    r_proto_policy_append_basic(ndnr, policy, "1.5", "Repository", global_prefix);
    r_proto_policy_append_namespace(ndnr, policy, "/");
    basename = ndn_charbuf_create();
    res = ndn_name_from_uri(basename, global_prefix);
    res |= ndn_name_from_uri(basename, "data/policy.xml");
    if (res < 0) {
        r_init_fail(ndnr, __LINE__, "Global prefix is not a valid URI", 0);
        return(-1);
    }
    ndnr->policy_name = ndn_charbuf_create(); // to detect writes to this name
    ndn_charbuf_append_charbuf(ndnr->policy_name, basename);
    ndn_create_version(ndnr->direct_client, basename, 0,
                       ndnr->starttime, ndnr->starttime_usec * 1000);
    policy_cob = ndnr_init_policy_cob(ndnr, ndnr->direct_client, basename,
                                      600, policy);
    // save the policy content object to the repository
    content = process_incoming_content(ndnr, ndnr->face0,
                                       (void *)policy_cob->buf,
                                       policy_cob->length, NULL);
    r_store_commit_content(ndnr, content);
    ndn_charbuf_destroy(&policy_cob);
    // make a link to the policy content object
    ndn_charbuf_destroy(&ndnr->policy_link_cob);
    ndnr->policy_link_cob = ndnr_init_policy_link_cob(ndnr, ndnr->direct_client,
                                                      basename);
    if (ndnr->policy_link_cob == NULL) {
        r_init_fail(ndnr, __LINE__, "Unable to create policy link object", 0);
        return(-1);
    }
    
    fd = open(ndn_charbuf_as_string(policyFileName), O_WRONLY | O_CREAT, 0666);
    if (fd < 0) {
        r_init_fail(ndnr, __LINE__, "Unable to open repoPolicy file for write", errno);
        return(-1);
    }
    lseek(fd, 0, SEEK_SET);
    res = write(fd, ndnr->policy_link_cob->buf, ndnr->policy_link_cob->length);
    if (res == -1) {
        r_init_fail(ndnr, __LINE__, "Unable to write repoPolicy file", errno);
        return(-1);
    }
    res = ftruncate(fd, ndnr->policy_link_cob->length);
    close(fd);
    if (res == -1) {
        r_init_fail(ndnr, __LINE__, "Unable to truncate repoPolicy file", errno);
        return(-1);
    }
    // parse the policy for later use
    if (r_proto_parse_policy(ndnr, policy->buf, policy->length, ndnr->parsed_policy) < 0) {
        r_init_fail(ndnr, __LINE__, "Unable to parse new repoPolicy file", 0);
        return(-1);
    }
    // get the pp->version from the policy_cob base name .../policy.xml/<ver>
    nc = ndn_indexbuf_create();
    ndn_name_split(basename, nc);
    res = ndn_name_comp_get(basename->buf, nc, nc->n - 2, &buf, &length);
    if (length != 7 || buf[0] != NDN_MARKER_VERSION) {
        r_init_fail(ndnr, __LINE__, "Unable to get repository policy object version", 0);
        return(-1);
    }
    memmove(ndnr->parsed_policy->version, buf, sizeof(ndnr->parsed_policy->version));
    ndn_indexbuf_destroy(&nc);
    ndn_charbuf_destroy(&basename);
    ndn_charbuf_destroy(&policy);
    ndn_charbuf_destroy(&policyFileName);
    return(0);
}

