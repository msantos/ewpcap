%%% @copyright 2012-2020 Michael Santos <michael.santos@gmail.com>
%%% All rights reserved.
%%%
%%% Redistribution and use in source and binary forms, with or without
%%% modification, are permitted provided that the following conditions
%%% are met:
%%%
%%% 1. Redistributions of source code must retain the above copyright notice,
%%% this list of conditions and the following disclaimer.
%%%
%%% 2. Redistributions in binary form must reproduce the above copyright
%%% notice, this list of conditions and the following disclaimer in the
%%% documentation and/or other materials provided with the distribution.
%%%
%%% 3. Neither the name of the copyright holder nor the names of its
%%% contributors may be used to endorse or promote products derived from
%%% this software without specific prior written permission.
%%%
%%% THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
%%% "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
%%% LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
%%% A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
%%% HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
%%% SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
%%% TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
%%% PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
%%% LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
%%% NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
%%% SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
-module(ewpcap).

-include("ewpcap.hrl").

-export([
    open/0, open/1, open/2,
    close/1,
    filter/2, filter/3,
    read/1, read/2,
    write/2,
    getifaddrs/0,
    dev/0,
    stats/1
]).

-define(PCAP_NETMASK_UNKNOWN, 4294967295).

-define(DLT_EN10MB, 1).

-type ewpcap_resource() :: #ewpcap_resource{}.

-type ewpcap_stat() :: #ewpcap_stat{}.

-export_type([ewpcap_resource/0, ewpcap_stat/0]).

-on_load({on_load, 0}).

%%--------------------------------------------------------------------
%%% NIF stubs
%%--------------------------------------------------------------------
on_load() ->
    case erlang:system_info(smp_support) of
        true -> erlang:load_nif(progname(), []);
        false -> {error, "Requires smp support (-smp enable)"}
    end.

pcap_compile(_, _, _, _) -> erlang:nif_error(not_implemented).

pcap_open_live(_, _, _, _, _, _, _) -> erlang:nif_error(not_implemented).

pcap_close(_) -> erlang:nif_error(not_implemented).

pcap_lookupdev() -> erlang:nif_error(not_implemented).

pcap_findalldevs() -> erlang:nif_error(not_implemented).

pcap_loop(_) -> erlang:nif_error(not_implemented).

pcap_sendpacket(_, _) -> erlang:nif_error(not_implemented).

pcap_stats(_) -> erlang:nif_error(not_implemented).

%%--------------------------------------------------------------------
%%% API
%%--------------------------------------------------------------------
-type time_unit() :: timestamp | microsecond.

-type open_options() :: [
    {snaplen, non_neg_integer()}
    | {promisc, boolean()}
    | {to_ms, non_neg_integer()}
    | {filter, iodata()}
    | {buffer, non_neg_integer()}
    | {monitor, boolean()}
    | {time_unit, time_unit()}
].

-spec open() -> {ok, ewpcap_resource()} | {error, string() | enomem}.
open() -> open(<<>>, []).

-spec open(iodata()) -> {ok, ewpcap_resource()} | {error, string() | enomem}.
open(Dev) -> open(Dev, []).

-spec open(iodata(), open_options()) ->
    {ok, ewpcap_resource()}
    | {error, string() | enomem}.
open(<<>>, Options) ->
    case pcap_lookupdev() of
        {ok, Dev} -> open(Dev, Options);
        Error -> Error
    end;
open(Dev, Options) when is_list(Options) ->
    Snaplen = proplists:get_value(snaplen, Options, 65535),
    Promisc = bool(proplists:get_value(promisc, Options, false)),
    To_ms = proplists:get_value(to_ms, Options, 500),
    Filter = proplists:get_value(filter, Options, <<>>),
    Buffer = proplists:get_value(buffer, Options, 0),
    Monitor = bool(proplists:get_value(monitor, Options, false)),
    TimeUnit = time_unit(proplists:get_value(time_unit, Options, timestamp)),
    case pcap_open_live(Dev, Snaplen, Promisc, To_ms, Buffer, Monitor, TimeUnit) of
        {ok, Socket} -> open_1(Socket, Options, Filter);
        Error -> Error
    end.

open_1(Socket, _Options, <<>>) ->
    open_2(Socket);
open_1(Socket, Options, Filter) ->
    case filter(Socket, Filter, Options) of
        ok -> open_2(Socket);
        Error -> Error
    end.

open_2(Socket) ->
    case loop(Socket) of
        ok -> {ok, Socket};
        Error -> Error
    end.

-spec close(ewpcap_resource()) -> ok.
close(#ewpcap_resource{res = Res}) -> pcap_close(Res).

-type filter_options() :: [
    {optimize, boolean()}
    | {netmask, non_neg_integer()}
].

-spec filter(ewpcap_resource(), iodata()) -> ok | {error, string() | enomem}.
filter(Res, Filter) -> filter(Res, Filter, []).

-spec filter(ewpcap_resource(), iodata(), filter_options()) ->
    ok
    | {error, string() | enomem}.
filter(#ewpcap_resource{res = Res}, Filter, Options) when is_binary(Filter); is_list(Filter) ->
    Optimize = bool(proplists:get_value(optimize, Options, true)),
    Netmask = mask(proplists:get_value(netmask, Options, ?PCAP_NETMASK_UNKNOWN)),
    Limit = proplists:get_value(limit, Options, 8192),
    case iolist_size(Filter) < Limit orelse Limit < 0 of
        true -> pcap_compile(Res, Filter, Optimize, Netmask);
        false -> {error, enomem}
    end.

-spec loop(ewpcap_resource()) -> ok | {error, files:posix()}.
loop(#ewpcap_resource{res = Res}) -> pcap_loop(Res).

-spec read(ewpcap_resource()) -> {ok, binary()} | {error, string()}.
read(Res) -> read(Res, infinity).

-spec read(ewpcap_resource(), infinity | non_neg_integer()) ->
    {ok, binary()}
    | {error, string() | eagain}.
read(#ewpcap_resource{ref = Ref}, Timeout) ->
    receive
        {ewpcap, Ref, _DatalinkType, _Time, _ActualLength, Packet} -> {ok, Packet};
        {ewpcap_error, Ref, Error} -> {error, Error}
    after Timeout -> {error, eagain}
    end.

-spec write(ewpcap_resource(), iodata()) -> ok | {error, string()}.
write(#ewpcap_resource{res = Res}, Data) when is_list(Data); is_binary(Data) ->
    pcap_sendpacket(Res, Data).

-spec dev() -> {ok, string()} | {error, string()}.
dev() -> pcap_lookupdev().

-spec getifaddrs() ->
    {ok, [] | [{string(), [proplists:proplist()]}]}
    | {error, string()}.
getifaddrs() ->
    case pcap_findalldevs() of
        {ok, Iflist} -> {ok, [iface(N) || N <- lists:reverse(Iflist)]};
        Error -> Error
    end.

-spec stats(ewpcap_resource()) -> {ok, ewpcap_stat()} | {error, string()}.
stats(#ewpcap_resource{res = Res}) -> pcap_stats(Res).

iface({If, Attr}) -> {If, addr(Attr)}.

addr(Attr) -> addr(Attr, []).

addr([], Attr) ->
    Attr;
addr([{Key, <<A, B, C, D>>} | T], Attr) ->
    addr(T, [{Key, {A, B, C, D}} | Attr]);
addr([{Key, <<A:16, B:16, C:16, D:16, E:16, F:16, G:16, H:16>>} | T], Attr) ->
    addr(T, [{Key, {A, B, C, D, E, F, G, H}} | Attr]);
addr([N | T], Attr) ->
    addr(T, [N | Attr]).

%%--------------------------------------------------------------------
%%% Internal functions
%%--------------------------------------------------------------------
bool(true) -> 1;
bool(false) -> 0.

time_unit(timestamp) -> 0;
time_unit(microsecond) -> 1.

mask(N) when is_integer(N) -> N;
mask({A, B, C, D}) -> A bsl 24 bor (B bsl 16) bor (C bsl 8) bor D.

progname() ->
    case code:priv_dir(?MODULE) of
        {error, bad_name} ->
            filename:join([filename:dirname(code:which(?MODULE)), "..", "priv", ?MODULE]);
        Dir ->
            filename:join([Dir, ?MODULE])
    end.
