ewpcap is a native Erlang interface to PCAP that can be used for reading
and writing packets from the network.

ewpcap is an experiment, meant to be a portable raw socket interface to
all the platforms that support Erlang and libpcap.

## WARNING

ewpcap was written and tested under Linux. But if you are using a
Unix system, it is much safer to use one of these projects:

* procket : https://github.com/msantos/procket

* epcap : https://github.com/msantos/epcap

The ewpcap interface will still go through some changes. For example,
the function names may change as may the packet tuple.

ewpcap hasn't been heavily tested. It will probably segfault.


## REQUIREMENTS

* libpcap/winpcap

  On Ubuntu: sudo apt-get install libpcap-dev

These libraries are not required but can be used with ewpcap:

* pkt: https://github.com/msantos/pkt.git

  Use pkt to decode/encode packets read from the network.

* privileges

ewpcap requires beam to be running with root privileges:

    * using sudo

        sudo erl -smp -pa ebin

    * using capabilities

        setcap cap_net_raw=ep /path/to/beam.smp

* SMP

SMP erlang must be enabled (erl -smp -pa ebin).


## COMPILING

    make


## EXPORTS

    open() -> {ok, Socket} | {error, Error}
    open(Dev) -> {ok, Socket} | {error, Error}
    open(Dev, Options) -> {ok, Socket} | {error, Error}
    
        Types   Dev = binary() | string()
                Error = enomem | pcap_error_string()
                Socket = resource()
                Options = [ Option ]
                Option = {promisc, boolean()}
                    | {snaplen, integer()}
                    | {to_ms, integer()}
                    | {filter, binary() | string()}
                    | FilterOpts

        Open a network interface and begin receiving packets.

        Dev is the name of the network device. If an empty binary (<<>>)
        is passed in, pcap will select a default interface.

        If an error occurs, the PCAP string describing the error is
        returned to the caller.

        open/1 and open/2 default to:

            * promiscuous mode disabled

            * a snaplen (packet length) of 65535 bytes

            * timeout set to 500 ms

            * no filter (all packets are received)

        For filter options, see filter/3.

        Packets are returned as messages to the caller:

            {ewpcap, Ref, DatalinkType, Time, Length, Packet}

        Ref is a reference identifying the socket handle.

        The DataLinkType is an integer representing the link layer,
        e.g., ethernet, Linux cooked socket.

        The Time is a tuple in the same format as erlang:now/0, {MegaSecs,
        Secs, MicroSecs}.

        The Length corresponds to the actual packet length on the
        wire. The captured packet may have been truncated. To get the
        captured packet length, use byte_size(Packet).

        The Packet is a binary holding the captured data.

    close(Socket) -> ok

        Closes the pcap descriptor.

    filter(Socket, Filter) -> ok | {error, Error}
    filter(Socket, Filter, Options) -> ok | {error, Error}

        Types   Socket = resource()
                Error = enomem | pcap_error_string()
                Options = [ Option ]
                Option = {optimize, boolean()}
                    | {netmask, integer()}

        Compile a PCAP filter and apply it to the PCAP descriptor.

    read(Socket) -> {ok, Packet}
    read(Socket, Timeout) -> {ok, Packet} | {error, eagain}

        Types   Socket = resource()
                Timeout = uint() | infinity
                Packet = binary()

        Convenience function wrapping receive, returning the packet
        contents.

    write(Socket) -> ok | {error, pcap_error_string()}

        Types   Socket = resource()

        Write the packet to the network. See pcap_sendpacket(3PCAP).

    dev() -> {ok, string()} | {error, pcap_error_string()}

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

## EXAMPLES

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

## TODO

* ewpcap, epcap, epcap\_compile ... confusing!

* pcap\_sendpacket may block

* pcap\_findalldevices blocks

* re-write as a port driver?
