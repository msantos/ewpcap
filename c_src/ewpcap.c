/* Copyright (c) 2012-2013, Michael Santos <michael.santos@gmail.com>
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

/* sockaddr, PF_* */
#if defined(WIN32) || defined(__WIN32__) || defined(__WIN32)
# include <Winsock2.h>
#else
# include <sys/types.h>
# include <sys/socket.h>
# include <netinet/in.h>
# include <arpa/inet.h>
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

ErlNifResourceType *EWPCAP_RESOURCE;

static ERL_NIF_TERM atom_ok;
static ERL_NIF_TERM atom_error;
static ERL_NIF_TERM atom_enomem;
static ERL_NIF_TERM atom_ewpcap;
static ERL_NIF_TERM atom_ewpcap_resource;
static ERL_NIF_TERM atom_ewpcap_error;

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
void ewpcap_send(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes);
void ewpcap_error(EWPCAP_STATE *ep, char *msg);


    static int
load(ErlNifEnv *env, void **priv_data, ERL_NIF_TERM load_info)
{
    EWPCAP_STATE *state = NULL;


    state = enif_alloc(sizeof(EWPCAP_STATE));
    if (state == NULL)
        return -1;

    atom_ok = enif_make_atom(env, "ok");
    atom_error = enif_make_atom(env, "error");
    atom_enomem = enif_make_atom(env, "enomem");
    atom_ewpcap = enif_make_atom(env, "ewpcap");
    atom_ewpcap_resource = enif_make_atom(env, "ewpcap_resource");
    atom_ewpcap_error = enif_make_atom(env, "ewpcap_error");

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

    return 0;
}

    void *
ewpcap_loop(void *arg)
{
    EWPCAP_STATE *ep = arg;
    int rv = 0;


    ep->env = enif_alloc_env();
    if (ep->env == NULL)
        goto ERR;

    rv = pcap_loop(ep->p, -1 /* loop forever */, ewpcap_send, (u_char *)ep);

    switch (rv) {
        case -2:
            /* break requested using pcap_breakloop */
            break;
        case -1:
            /* pcap_loop error: the pcap handle may not be valid at this
               point, so we do not return an error */
            break;

        default:
            break;
    }

ERR:
    /* env is freed in resource cleanup */
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
        return;

    if (!enif_alloc_binary(h->caplen, &buf)) {
        pcap_breakloop(ep->p);
        return;
    }

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
        pcap_breakloop(ep->p);

    enif_clear_env(ep->env);
}

    void
ewpcap_error(EWPCAP_STATE *ep, char *msg)
{
    int rv = 0;

    if (ep->p == NULL)
        return;

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
        pcap_breakloop(ep->p);

    enif_clear_env(ep->env);
}


    static ERL_NIF_TERM
nif_pcap_open_live(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    ErlNifBinary device = {0};
    int snaplen = 0;
    int promisc = 0;
    int to_ms = 0;
    char errbuf[PCAP_ERRBUF_SIZE] = {0};

    EWPCAP_STATE *ep = NULL;
    ERL_NIF_TERM res = {0};
    ERL_NIF_TERM ref = {0};


    if (!enif_inspect_iolist_as_binary(env, argv[0], &device))
        return enif_make_badarg(env);

    if (!enif_get_int(env, argv[1], &snaplen))
        return enif_make_badarg(env);

    if (!enif_get_int(env, argv[2], &promisc))
        return enif_make_badarg(env);

    if (!enif_get_int(env, argv[3], &to_ms))
        return enif_make_badarg(env);

    /* NULL terminate the device name */
    if (device.size > 0 && !enif_realloc_binary(&device, device.size+1))
        return enif_make_tuple2(env, atom_error, atom_enomem);

    device.data[device.size-1] = '\0';

    ep = enif_alloc_resource(EWPCAP_RESOURCE, sizeof(EWPCAP_STATE));

    if (ep == NULL)
        return enif_make_tuple2(env, atom_error, atom_enomem);


    /* "any" is a Linux only virtual dev */
    ep->p = pcap_open_live((device.size == 0 ? "any" : (char *)device.data),
            snaplen, promisc, to_ms, errbuf);

    if (ep->p == NULL)
        return enif_make_tuple2(env,
                atom_error,
                enif_make_string(env, errbuf, ERL_NIF_LATIN1));

    ep->datalink = pcap_datalink(ep->p);
    (void)enif_self(env, &ep->pid);

    ep->term_env = enif_alloc_env();
    if (ep->term_env == NULL) {
        pcap_close(ep->p);
        return enif_make_tuple2(env, atom_error, atom_enomem);
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
}

    static ERL_NIF_TERM
nif_pcap_close(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    EWPCAP_STATE *ep = NULL;


    if (!enif_get_resource(env, argv[0], EWPCAP_RESOURCE, (void **)&ep) || ep->p == NULL)
        return enif_make_badarg(env);

    pcap_breakloop(ep->p);
    pcap_close(ep->p);
    ep->p = NULL;

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
                goto ERR; \
 \
            (void)memcpy(buf.data, &(sin->sin_addr.s_addr), buf.size); \
        } \
        break; \
        case PF_INET6: { \
            struct sockaddr_in6 *sin = (struct sockaddr_in6 *)saddr; \
 \
            if (!enif_alloc_binary(sizeof(sin->sin6_addr), &buf)) \
                goto ERR; \
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
                    enif_make_string(env, alldevsp->description, ERL_NIF_LATIN1)),
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

ERR:
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


    if (!enif_get_resource(env, argv[0], EWPCAP_RESOURCE, (void **)&ep) || ep->p == NULL)
        return enif_make_badarg(env);

    if (enif_thread_create("ewpcap_loop", &ep->tid, ewpcap_loop, ep, NULL) != 0)
        return enif_make_tuple2(env, atom_error, enif_make_atom(env, erl_errno_id(errno)));

    return atom_ok;
}

    static ERL_NIF_TERM
nif_pcap_compile(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    EWPCAP_STATE *ep = NULL;
    ErlNifBinary filter = {0};
    int optimize = 0;
    u_int32_t netmask = 0;

    struct bpf_program fp = {0};


    if (!enif_get_resource(env, argv[0], EWPCAP_RESOURCE, (void **)&ep) || ep->p == NULL)
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

    if (pcap_compile(ep->p, &fp, (const char *)filter.data,
                optimize, netmask) != 0)
        return enif_make_tuple2(env,
                atom_error,
                enif_make_string(env, pcap_geterr(ep->p), ERL_NIF_LATIN1));

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


    if (!enif_get_resource(env, argv[0], EWPCAP_RESOURCE, (void **)&ep) || ep->p == NULL)
        return enif_make_badarg(env);

    if (!enif_inspect_iolist_as_binary(env, argv[1], &buf))
        return enif_make_badarg(env);

    if (pcap_sendpacket(ep->p, buf.data, buf.size) < 0)
        return enif_make_tuple2(env,
                atom_error,
                enif_make_string(env, pcap_geterr(ep->p), ERL_NIF_LATIN1));

    return atom_ok;
}

    void
ewpcap_cleanup(ErlNifEnv *env, void *obj)
{
    EWPCAP_STATE *ep = obj;

    if (ep->p == NULL)
        return;

    pcap_breakloop(ep->p);
    pcap_close(ep->p);

    if (ep->env)
        enif_free_env(ep->env);

    if (ep->term_env)
        enif_free_env(ep->term_env);

    (void)memset(ep, 0, sizeof(EWPCAP_STATE));
}


static ErlNifFunc nif_funcs[] = {
    {"pcap_compile", 4, nif_pcap_compile},
    {"pcap_open_live", 4, nif_pcap_open_live},
    {"pcap_close", 1, nif_pcap_close},
    {"pcap_loop", 1, nif_pcap_loop},
    {"pcap_sendpacket", 2, nif_pcap_sendpacket},
    {"pcap_lookupdev", 0, nif_pcap_lookupdev},
    {"pcap_findalldevs", 0, nif_pcap_findalldevs}
};

ERL_NIF_INIT(ewpcap, nif_funcs, load, NULL, NULL, NULL)
