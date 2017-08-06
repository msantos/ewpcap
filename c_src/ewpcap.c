/* Copyright (c) 2012-2017, Michael Santos <michael.santos@gmail.com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 *
 * Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 *
 * Neither the name of the author nor the names of its contributors
 * may be used to endorse or promote products derived from this software
 * without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
#include <pcap.h>
#include <string.h>
#include <errno.h>

#if defined(__SVR4) && defined(__sun)
#define u_int8_t            uint8_t
#define u_int16_t           uint16_t
#define u_int32_t           uint32_t
#define u_int64_t           uint64_t
#endif

/* sockaddr, PF_* */
#if defined(WIN32) || defined(__WIN32__) || defined(__WIN32)
# include <Winsock2.h>
#else
# include <sys/types.h>
# include <sys/socket.h>
# include <netinet/in.h>
# include <arpa/inet.h>
# define RFMON_SUPPORTED
#endif

#include "erl_nif.h"
#include "erl_driver.h"

#if defined(WIN32) || defined(__WIN32__) || defined(__WIN32)
TWinDynDriverCallbacks WinDynDriverCallbacks;
#endif

typedef struct _ewpcap_state {
    ErlNifEnv *env;
    ErlNifEnv *term_env;
    ErlNifPid pid;
    ErlNifTid tid;
    ERL_NIF_TERM ref;
    pcap_t *p;
    int datalink;
} EWPCAP_STATE;

typedef struct {
    ErlNifMutex *lock;
} EWPCAP_PRIV;

ErlNifResourceType *EWPCAP_RESOURCE;

static ERL_NIF_TERM atom_ok;
static ERL_NIF_TERM atom_error;
static ERL_NIF_TERM atom_enomem;
static ERL_NIF_TERM atom_ewpcap;
static ERL_NIF_TERM atom_ewpcap_resource;
static ERL_NIF_TERM atom_ewpcap_error;
static ERL_NIF_TERM atom_ewpcap_stat;

/* pcap_findalldevices() */
static ERL_NIF_TERM atom_description;
static ERL_NIF_TERM atom_addr;
static ERL_NIF_TERM atom_flag;
static ERL_NIF_TERM atom_netmask;
static ERL_NIF_TERM atom_broadaddr;
static ERL_NIF_TERM atom_dstaddr;
static ERL_NIF_TERM atom_loopback;

void *ewpcap_loop(void *arg);
void ewpcap_cleanup(ErlNifEnv *env, void *obj);
void ewpcap_send(u_char *user, const struct pcap_pkthdr *h,
        const u_char *bytes);
void ewpcap_error(EWPCAP_STATE *ep, char *msg);


    static int
load(ErlNifEnv *env, void **priv_data, ERL_NIF_TERM load_info)
{
    EWPCAP_PRIV *priv = NULL;

    atom_ok = enif_make_atom(env, "ok");
    atom_error = enif_make_atom(env, "error");
    atom_enomem = enif_make_atom(env, "enomem");
    atom_ewpcap = enif_make_atom(env, "ewpcap");
    atom_ewpcap_resource = enif_make_atom(env, "ewpcap_resource");
    atom_ewpcap_error = enif_make_atom(env, "ewpcap_error");
    atom_ewpcap_stat = enif_make_atom(env, "ewpcap_stat");

    atom_description = enif_make_atom(env, "description");
    atom_addr = enif_make_atom(env, "addr");
    atom_flag = enif_make_atom(env, "flag");
    atom_netmask = enif_make_atom(env, "netmask");
    atom_broadaddr = enif_make_atom(env, "broadaddr");
    atom_dstaddr = enif_make_atom(env, "dstaddr");
    atom_loopback = enif_make_atom(env, "loopback");

    if ( (EWPCAP_RESOURCE = enif_open_resource_type(env, NULL,
            "ewpcap_resource", ewpcap_cleanup,
            ERL_NIF_RT_CREATE, NULL)) == NULL)
        return -1;

    priv = enif_alloc(sizeof(EWPCAP_PRIV));
    if (priv == NULL)
        return -1;

    priv->lock = enif_mutex_create("ewpcap_lock");
    if (priv->lock == NULL)
        return -1;

    *priv_data = priv;

    return 0;
}

    static void
unload(ErlNifEnv *env, void *priv_data)
{
    EWPCAP_PRIV *priv = priv_data;
    enif_mutex_destroy(priv->lock);
    enif_free(priv);
}

    void *
ewpcap_loop(void *arg)
{
    EWPCAP_STATE *ep = arg;
    int rv = 0;

    rv = pcap_loop(ep->p, -1 /* loop forever */, ewpcap_send, (u_char *)ep);

    switch (rv) {
        case -2:
            /* break requested using pcap_breakloop */
            break;
        case -1:
            ewpcap_error(ep, pcap_geterr(ep->p));
            break;

        default:
            break;
    }

    return NULL;
}

    void
ewpcap_send(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes)
{
    EWPCAP_STATE *ep = (EWPCAP_STATE *)user;
    ErlNifBinary buf = {0};
    int rv = 0;


    /* XXX no way to indicate an error? */
    if (ep->p == NULL)
        enif_thread_exit(NULL);

    if (!enif_alloc_binary(h->caplen, &buf))
        enif_thread_exit(NULL);

    (void)memcpy(buf.data, bytes, buf.size);

    /* {ewpcap, Ref, DatalinkType, Time, ActualLength, Packet} */
    rv = enif_send(
        NULL,
        &ep->pid,
        ep->env,
        enif_make_tuple6(ep->env,
            atom_ewpcap,
            enif_make_copy(ep->env, ep->ref),
            enif_make_int(ep->env, ep->datalink),
            enif_make_tuple3(ep->env,
                enif_make_ulong(ep->env, abs(h->ts.tv_sec / 1000000)),
                enif_make_ulong(ep->env, h->ts.tv_sec % 1000000),
                enif_make_ulong(ep->env, h->ts.tv_usec)
                ),
            enif_make_ulong(ep->env, h->len),
            enif_make_binary(ep->env, &buf)
        )
    );

    if (!rv)
        enif_thread_exit(NULL);

    enif_clear_env(ep->env);
}

    void
ewpcap_error(EWPCAP_STATE *ep, char *msg)
{
    int rv = 0;

    if (ep->p == NULL)
        enif_thread_exit(NULL);

    /* {ewpcap_error, Ref, Error} */
    rv = enif_send(
        NULL,
        &ep->pid,
        ep->env,
        enif_make_tuple3(ep->env,
            atom_ewpcap_error,
            enif_make_copy(ep->env, ep->ref),
            enif_make_string(ep->env, msg, ERL_NIF_LATIN1)
        )
    );

    if (!rv)
        enif_thread_exit(NULL);

    enif_clear_env(ep->env);
}


    static ERL_NIF_TERM
nif_pcap_open_live(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    ErlNifBinary device = {0};
    int snaplen = 0;
    int promisc = 0;
    int to_ms = 0;
    int buffer_size = 0;
    int rfmon = 0;
    char errbuf[PCAP_ERRBUF_SIZE] = {0};

    EWPCAP_STATE *ep = NULL;
    ERL_NIF_TERM res = {0};
    ERL_NIF_TERM ref = {0};

    ERL_NIF_TERM t = {0};

    if (!enif_inspect_iolist_as_binary(env, argv[0], &device))
        return enif_make_badarg(env);

    if (!enif_get_int(env, argv[1], &snaplen))
        return enif_make_badarg(env);

    if (!enif_get_int(env, argv[2], &promisc))
        return enif_make_badarg(env);

    if (!enif_get_int(env, argv[3], &to_ms))
        return enif_make_badarg(env);

    if (!enif_get_int(env, argv[4], &buffer_size))
        return enif_make_badarg(env);

    if (!enif_get_int(env, argv[5], &rfmon))
        return enif_make_badarg(env);

    /* NULL terminate the device name */
    if (device.size > 0) {
        if (!enif_realloc_binary(&device, device.size+1))
            return enif_make_tuple2(env, atom_error, atom_enomem);

        device.data[device.size-1] = '\0';
    }

    ep = enif_alloc_resource(EWPCAP_RESOURCE, sizeof(EWPCAP_STATE));

    if (ep == NULL)
        return enif_make_tuple2(env, atom_error, atom_enomem);

    /* "any" is a Linux only virtual dev */
    ep->p = pcap_create((device.size == 0 ? "any" : (char *)device.data),
            errbuf);

    if (ep->p == NULL) {
        t = enif_make_tuple2(env,
                atom_error,
                enif_make_string(env, errbuf, ERL_NIF_LATIN1));
        goto ERROR_LABEL;
    }

    /* Set the snaplen */
    (void)pcap_set_snaplen(ep->p, snaplen);

    /* Set promiscuous mode */
    (void)pcap_set_promisc(ep->p, promisc);

    /* Set timeout */
    (void)pcap_set_timeout(ep->p, to_ms);

    /* Set buffer size */
    if (buffer_size > 0)
        (void)pcap_set_buffer_size(ep->p, buffer_size);

#if defined(RFMON_SUPPORTED)
    /* Set monitor mode */
    if (pcap_can_set_rfmon(ep->p) == 1)
        (void)pcap_set_rfmon(ep->p, rfmon);
#endif

    /* Return failure on error and warnings */
    if (pcap_activate(ep->p) != 0) {
        t = enif_make_tuple2(env,
                atom_error,
                enif_make_string(env, pcap_geterr(ep->p), ERL_NIF_LATIN1));
        goto ERROR_LABEL;
    }

    ep->datalink = pcap_datalink(ep->p);
    ep->tid = enif_thread_self();
    (void)enif_self(env, &ep->pid);

    ep->env = enif_alloc_env();
    if (ep->env == NULL) {
        t = enif_make_tuple2(env, atom_error, atom_enomem);
        goto ERROR_LABEL;
    }

    ep->term_env = enif_alloc_env();
    if (ep->term_env == NULL) {
        t = enif_make_tuple2(env, atom_error, atom_enomem);
        goto ERROR_LABEL;
    }

    ep->ref = enif_make_ref(ep->term_env);
    ref = enif_make_copy(env, ep->ref);

    res = enif_make_resource(env, ep);
    enif_release_resource(ep);

    return enif_make_tuple2(env,
            atom_ok,
            enif_make_tuple3(env,
                atom_ewpcap_resource,
                ref,
                res));

ERROR_LABEL:
    if (ep->p)
        pcap_close(ep->p);

    if (ep->env)
        enif_free_env(ep->env);

    enif_release_resource(ep);

    return t;
}

    static ERL_NIF_TERM
nif_pcap_close(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    EWPCAP_STATE *ep = NULL;


    if (!enif_get_resource(env, argv[0], EWPCAP_RESOURCE, (void **)&ep)
            || ep->p == NULL)
        return enif_make_badarg(env);

    ewpcap_cleanup(env, ep);

    return atom_ok;
}

    static ERL_NIF_TERM
nif_pcap_lookupdev(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    char *dev = NULL;
    char errbuf[PCAP_ERRBUF_SIZE] = {0};


    dev = pcap_lookupdev(errbuf);

    if (dev == NULL)
        return enif_make_tuple2(env,
                atom_error,
                enif_make_string(env, errbuf, ERL_NIF_LATIN1));

    return enif_make_tuple2(env,
            atom_ok,
            enif_make_string(env, dev, ERL_NIF_LATIN1));
}

#define MAKE_ADDR(env, attr, key, addrp) do { \
    ErlNifBinary buf = {0}; \
    struct sockaddr *saddr = addrp->key; \
 \
    if (saddr == NULL) \
        break; \
 \
    switch (addrp->addr->sa_family) { \
        case PF_INET: { \
            struct sockaddr_in *sin = (struct sockaddr_in *)saddr; \
 \
            if (!enif_alloc_binary(sizeof(sin->sin_addr.s_addr), &buf)) \
                goto ERROR_LABEL; \
 \
            (void)memcpy(buf.data, &(sin->sin_addr.s_addr), buf.size); \
        } \
        break; \
        case PF_INET6: { \
            struct sockaddr_in6 *sin = (struct sockaddr_in6 *)saddr; \
 \
            if (!enif_alloc_binary(sizeof(sin->sin6_addr), &buf)) \
                goto ERROR_LABEL; \
 \
            (void)memcpy(buf.data, &(sin->sin6_addr), buf.size); \
        } \
        break; \
    } \
 \
    attr = enif_make_list_cell(env, \
        enif_make_tuple2(env, \
            atom_##key, \
            enif_make_binary(env, &buf)), \
        attr); \
 \
} while (0)

    static ERL_NIF_TERM
nif_pcap_findalldevs(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    pcap_if_t *alldevsp = NULL;
    char errbuf[PCAP_ERRBUF_SIZE] = {0};

    ERL_NIF_TERM dev = {0};


    if (pcap_findalldevs(&alldevsp, errbuf) < 0)
        return enif_make_tuple2(env,
                atom_error,
                enif_make_string(env, errbuf, ERL_NIF_LATIN1));


    dev = enif_make_list(env, 0);

    /* similar to inet:getifaddrs/0, except return binaries
     * for addresses:
     *  [{"lo", [
     *      {description, "..."},
     *      {flag, [loopback]},
     *      {address, <<>>},
     *      {netmask, <<>>},
     *      {broaddr, <<>>},
     *      {dstaddr, <<>>}
     *      ]}]
     */
    for ( ; alldevsp != NULL; alldevsp = alldevsp->next) {
        ERL_NIF_TERM attr = {0};
        ERL_NIF_TERM flags = {0};
        pcap_addr_t *sa = NULL;

        /* interface attributes */
        attr = enif_make_list(env, 0);

        /* interface flags */
        flags = enif_make_list(env, 0);

        if (alldevsp->description)
            attr = enif_make_list_cell(env,
                enif_make_tuple2(env,
                    atom_description,
                    enif_make_string(env, alldevsp->description,
                        ERL_NIF_LATIN1)),
                attr);

        if (alldevsp->flags & PCAP_IF_LOOPBACK) {
            flags = enif_make_list_cell(env, atom_loopback, flags);

            attr = enif_make_list_cell(env,
                enif_make_tuple2(env, atom_flag, flags), attr);
        }

        for (sa = alldevsp->addresses; sa != NULL; sa = sa->next) {
            if (sa->addr == NULL)
            continue;

            switch (sa->addr->sa_family) {
            case PF_INET:
            case PF_INET6:
                break;
            default:
                /* unsupported */
                continue;
            }

            /* address */
            MAKE_ADDR(env, attr, addr, sa);

            /* netmask */
            MAKE_ADDR(env, attr, netmask, sa);

            /* broadaddr */
            MAKE_ADDR(env, attr, broadaddr, sa);

            /* dstaddr */
            MAKE_ADDR(env, attr, dstaddr, sa);
        }

        dev = enif_make_list_cell(env,
            enif_make_tuple2(env,
                enif_make_string(env, alldevsp->name, ERL_NIF_LATIN1),
                attr),
            dev);
    }

    pcap_freealldevs(alldevsp);

    return enif_make_tuple2(env,
            atom_ok,
            dev);

ERROR_LABEL:
    pcap_freealldevs(alldevsp);

    /* MAKE_ADDR macro */
    return enif_make_tuple2(env,
            atom_error,
            atom_enomem);
}

    static ERL_NIF_TERM
nif_pcap_loop(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    EWPCAP_STATE *ep = NULL;

    if (!enif_get_resource(env, argv[0], EWPCAP_RESOURCE, (void **)&ep)
            || ep->p == NULL)
        return enif_make_badarg(env);

    if (!enif_equal_tids(ep->tid, enif_thread_self()))
        return enif_make_tuple2(env, atom_error, enif_make_atom(env, erl_errno_id(EAGAIN)));

    if (enif_thread_create("ewpcap_loop", &ep->tid, ewpcap_loop, ep, NULL) != 0)
        return enif_make_tuple2(env, atom_error, enif_make_atom(env, erl_errno_id(errno)));

    return atom_ok;
}

    static ERL_NIF_TERM
nif_pcap_compile(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    EWPCAP_STATE *ep = NULL;
    EWPCAP_PRIV *priv = NULL;
    ErlNifBinary filter = {0};
    int optimize = 0;
    u_int32_t netmask = 0;

    struct bpf_program fp = {0};

    priv = enif_priv_data(env);

    if (!enif_get_resource(env, argv[0], EWPCAP_RESOURCE, (void **)&ep)
            || ep->p == NULL)
        return enif_make_badarg(env);

    if (!enif_inspect_iolist_as_binary(env, argv[1], &filter))
        return enif_make_badarg(env);

    if (!enif_get_int(env, argv[2], &optimize))
        return enif_make_badarg(env);

    if (!enif_get_uint(env, argv[3], &netmask))
        return enif_make_badarg(env);

    /* NULL terminate the filter */
    if (!enif_realloc_binary(&filter, filter.size+1))
        return enif_make_tuple2(env, atom_error, atom_enomem);

    filter.data[filter.size-1] = '\0';

    enif_mutex_lock(priv->lock);

    if (pcap_compile(ep->p, &fp, (const char *)filter.data,
                optimize, netmask) != 0) {
        enif_mutex_unlock(priv->lock);
        return enif_make_tuple2(env,
                atom_error,
                enif_make_string(env, pcap_geterr(ep->p), ERL_NIF_LATIN1));
    }

    enif_mutex_unlock(priv->lock);

    if (pcap_setfilter(ep->p, &fp) < 0)
        return enif_make_tuple2(env,
                atom_error,
                enif_make_string(env, pcap_geterr(ep->p), ERL_NIF_LATIN1));

    return atom_ok;
}

    static ERL_NIF_TERM
nif_pcap_sendpacket(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    EWPCAP_STATE *ep = NULL;
    ErlNifBinary buf = {0};


    if (!enif_get_resource(env, argv[0], EWPCAP_RESOURCE, (void **)&ep)
            || ep->p == NULL)
        return enif_make_badarg(env);

    if (!enif_inspect_iolist_as_binary(env, argv[1], &buf))
        return enif_make_badarg(env);

    if (pcap_sendpacket(ep->p, buf.data, buf.size) < 0)
        return enif_make_tuple2(env,
                atom_error,
                enif_make_string(env, pcap_geterr(ep->p), ERL_NIF_LATIN1));

    return atom_ok;
}

    static ERL_NIF_TERM
nif_pcap_stats(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    EWPCAP_STATE *ep = NULL;
    struct pcap_stat ps = {0};

    if (!enif_get_resource(env, argv[0], EWPCAP_RESOURCE, (void **)&ep)
            || ep->p == NULL)
        return enif_make_badarg(env);

    if (pcap_stats(ep->p, &ps))
        return enif_make_tuple2(env,
                atom_error,
                enif_make_string(env, pcap_geterr(ep->p), ERL_NIF_LATIN1));

    return enif_make_tuple2(env,
            atom_ok,
            enif_make_tuple5(env,
                atom_ewpcap_stat,
                enif_make_uint(env, ps.ps_recv),
                enif_make_uint(env, ps.ps_drop),
                enif_make_uint(env, ps.ps_ifdrop),
                enif_make_uint(env, 0)
                ));
}

    void
ewpcap_cleanup(ErlNifEnv *env, void *obj)
{
    EWPCAP_STATE *ep = obj;

    if (ep->p == NULL)
        return;

    pcap_breakloop(ep->p);

    if (!enif_equal_tids(ep->tid, enif_thread_self()))
        (void)enif_thread_join(ep->tid, NULL);

    if (ep->env)
        enif_free_env(ep->env);

    pcap_close(ep->p);

    if (ep->term_env)
        enif_free_env(ep->term_env);

    ep->env = NULL;
    ep->term_env = NULL;
    ep->tid = enif_thread_self();
    ep->p = NULL;
}

static ErlNifFunc nif_funcs[] = {
    {"pcap_compile", 4, nif_pcap_compile},
    {"pcap_open_live", 6, nif_pcap_open_live},
    {"pcap_close", 1, nif_pcap_close, ERL_NIF_DIRTY_JOB_IO_BOUND},
    {"pcap_loop", 1, nif_pcap_loop},
    {"pcap_sendpacket", 2, nif_pcap_sendpacket},
    {"pcap_lookupdev", 0, nif_pcap_lookupdev},
    {"pcap_findalldevs", 0, nif_pcap_findalldevs},
    {"pcap_stats", 1, nif_pcap_stats}
};

ERL_NIF_INIT(ewpcap, nif_funcs, load, NULL, NULL, unload)
