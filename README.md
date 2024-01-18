[![Package Version](https://img.shields.io/hexpm/v/ewpcap)](https://hex.pm/packages/ewpcap)
[![Hex Docs](https://img.shields.io/badge/hex-docs)](https://hexdocs.pm/ewpcap/)

ewpcap is a native Erlang interface to PCAP that can be used for reading
and writing packets from the network.

ewpcap is meant to be a portable raw socket interface to all the platforms
that support Erlang and libpcap.

## WARNING

ewpcap was written and tested under Linux. But if you are using a
Unix system, you may want to use one of these projects instead:

* procket : https://github.com/msantos/procket

* epcap : https://github.com/msantos/epcap

## REQUIREMENTS

* libpcap/winpcap

  On Ubuntu: sudo apt-get install libpcap-dev

These libraries are not required but can be used with ewpcap:

* pkt: https://github.com/msantos/pkt.git

  Use pkt to decode/encode packets read from the network.

* privileges

ewpcap requires beam to be running with root privileges:

```
* using sudo

    sudo erl -pa ebin

* using capabilities

    setcap cap_net_raw=ep /path/to/beam.smp
```

## COMPILING

```
rebar3 do clean, compile, ct
```

## DATA TYPES

```
ewpcap_resource()

    A record returned by open/0,1,2.

    The record contains 2 fields:

        * res: an NIF resource associated with the pcap socket. The
               pcap process terminates when this resource is garbage
               collected.

        * ref: reference to socket handle in packet tuple
```

## EXPORTS

```
open() -> {ok, Socket} | {error, Error}
open(Dev) -> {ok, Socket} | {error, Error}
open(Dev, Options) -> {ok, Socket} | {error, Error}

    Types   Dev = binary() | string()
            Error = enomem | string()
            Socket = resource()
            Options = [ Option ]
            Option = {promisc, boolean()}
                | {snaplen, integer()}
                | {timeout, immediate | infinity | non_neg_integer()}
                | {buffer, integer()}
                | {monitor, boolean()}
                | {filter, iolist()}
                | {time_unit, timestamp | microsecond}
                | FilterOpts

    Open a network interface and begin receiving packets.

    The returned Socket in the 'ok' tuple must be kept by the
    process. When the socket goes out of scope, the pcap filter will
    be shut down and all resources associated with the socket will
    be freed. See also close/1.

    Dev is the name of the network device. If an empty binary (<<>>)
    is passed in, pcap will select a default interface.

    If an error occurs, the PCAP string describing the error is
    returned to the caller.

    open/1 and open/2 default to:

        * promiscuous mode disabled

        * a snaplen (packet length) of 65535 bytes

        * uses immediate mode

        * the time unit is an erlang timestamp in the same format
          as now/0

        * no filter (all packets are received)

    The `timeout` option sets `pcap_set_timeout(3PCAP)` and
    `pcap_set_immediate_mode(3PCAP)`. By default, ewpcap uses
    `immediate` mode and returns packets as they are received.
    Setting timeout to an integer value disables `immediate` mode
    and buffers any packets until either the timeout is reached or
    the buffer is filled.

    If ewpcap is dropping packets (see stats/1), the PCAP buffer
    size can be increased (should be some multiple of the snaplen).

    Wireless devices can be set to use monitor mode (rfmon) by
    passing in the 'monitor' option.

    The timestamp in the message can be formatted either as a now/0
    tuple or returned in microseconds.

    For filter options, see filter/3.

    Packets are returned as messages to the caller:

        {ewpcap, Ref, DatalinkType, Time, Length, Packet}

    Ref is a reference identifying the socket handle.

    The DataLinkType is an integer representing the link layer,
    e.g., ethernet, Linux cooked socket.

    The Time is a tuple in the same format as erlang:now/0, {MegaSecs,
    Secs, MicroSecs} or microseconds.

    The Length corresponds to the actual packet length on the
    wire. The captured packet may have been truncated. To get the
    captured packet length, use byte_size(Packet).

    The Packet is a binary holding the captured data.

    Errors will be sent to the caller and the pcap filter will
    be terminated:

        {ewpcap_error, Ref, Error}

close(Socket) -> ok

    Closes the pcap descriptor. See "SCHEDULER LATENCY".

filter(Socket, Filter) -> ok | {error, Error}
filter(Socket, Filter, Options) -> ok | {error, Error}

    Types   Socket = resource()
            Filter = iolist()
            Error = enomem | string()
            Options = [ Option ]
            Option = {optimize, boolean()}
                | {netmask, integer()}
                | {limit, integer()}

    Compile a PCAP filter and apply it to the PCAP descriptor.

    Since the library passes the filter string to pcap_compile(3PCAP)
    directly, any bugs in pcap_compile() may cause the Erlang VM
    to crash. Do not use filters from untrusted sources.

    Filters are limited to 8192 bytes by default since it may be
    possible for very large filters to cause a stack overflow. For
    example:

        ewpcap:open(<<>>, [{filter, string:copies("ip and ", 50000) ++ "ip"}, {limit, -1}])

read(Socket) -> {ok, Packet}
read(Socket, Timeout) -> {ok, Packet} | {error, Error}

    Types   Socket = resource()
            Timeout = uint() | infinity
            Packet = binary()
            Error = eagain | string()

    Convenience function wrapping receive, returning the packet
    contents.

write(Socket, Packet) -> ok | {error, string()}

    Types   Socket = resource()
            Packet = iodata()

    Write the packet to the network. See pcap_sendpacket(3PCAP).

dev() -> {ok, string()} | {error, string()}

    Returns the default device used by PCAP.

getifaddrs() -> {ok, Iflist} | {error, posix()}

    Types   Iflist = [{Ifname, [Ifopt]}]
            Ifname = string()
            Ifopt = {flag, [Flag]}
                | {addr, Addr}
                | {netmask, Netmask}
                | {broadaddr, Broadaddr}
                | {dstaddr, Dstaddr}
                | {description, string()}
            Flag = loopback
            Addr = Netmask = Broadaddr = Dstaddr = ip_address()

    Returns a list of interfaces. Ifname can be used as the first
    parameter to open/1 and open/2.

    This function is modelled on inet:getifaddrs/0 but uses
    pcap_findalldevs(3PCAP) to look up the interface attributes:

        * getifaddrs/0 may return pseudo devices, such as the "any"
          device on Linux

        * getifaddrs/0 will only return the list of devices that
          can be used with open/1 and open/2. An empty list ({ok,
          []}) may be returned if the user does not have permission
          to open any of the system interfaces

stats(Socket) -> {ok, #ewpcap_stat{}} | {error, string()}

    Types   Socket = resource()

    To use the return value as a record, include the header:

        -include_lib("ewpcap/include/ewpcap.hrl").

    stats/1 returns statistics about dropped packets. See
    pcap_stats(3PCAP) for details.

    The ewpcap_stat records contains these fields:

        recv : number of packets received

        drop : number of packets dropped due to insufficient buffer

        ifdrop : number of packets dropped by the network interface

        capt : always 0 (was number of packets received by the application (Win32 only))
```

## SCHEDULER LATENCY

In normal usage, ewpcap does not perform any blocking operations that
could interfere with the scheduler. For example, spawning one or more
long running pcap processes is scheduler friendly.

To confirm, run:

```
erlang:system_monitor(self(), [{long_schedule, 10}]).
```

ewpcap may block when stopping the pcap process. This situation might
occur if rapidly spawning and garbage collecting pcap processes:

```
% Don't do this: ewpcap resource freed when spawned processes exit
N = 100,
[ spawn(fun() -> ewpcap:open(<<>>, [{filter, "tcp and port 9876"}]), ok end)
    || X <- lists:seq(1,N) ].
```

However, if you need to do it, there are some workarounds:

* decrease the pcap timeout

```
% Set timeout to 1 ms
ewpcap:open(<<>>, [{filter, "tcp"}, {timeout, 1}]).
```

* explicitly do resource cleanup on a dirty scheduler

```
{ok, Socket} = ewpcap:open(<<>>, [{filter, "tcp"}]),
ewpcap:close(Socket)
```

## DISABLING DIRTY SCHEDULER SUPPORT

Use of the dirty scheduler can be disabled by setting an environment
variable:

```
EWPCAP_DISABLE_DIRTY_SCHEDULER=1 rebar3 do clean, compile
```

It is safe to disable for normal operation (but see "SCHEDULER LATENCY").

## EXAMPLES

```
    -module(icmp_resend).
    -export([start/1]).

    % icmp_resend:start("eth0").
    start(Dev) ->
        {ok, Socket} = ewpcap:open(Dev, [{filter, "icmp"}]),
        resend(Socket).

    resend(Socket) ->
        {ok, Packet} = ewpcap:read(Socket),
        ok = ewpcap:write(Socket, Packet),
        resend(Socket).
```

## TODO
