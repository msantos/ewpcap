%% Copyright (c) 2012-2013, Michael Santos <michael.santos@gmail.com>
%% All rights reserved.
%% 
%% Redistribution and use in source and binary forms, with or without
%% modification, are permitted provided that the following conditions
%% are met:
%% 
%% Redistributions of source code must retain the above copyright
%% notice, this list of conditions and the following disclaimer.
%% 
%% Redistributions in binary form must reproduce the above copyright
%% notice, this list of conditions and the following disclaimer in the
%% documentation and/or other materials provided with the distribution.
%% 
%% Neither the name of the author nor the names of its contributors
%% may be used to endorse or promote products derived from this software
%% without specific prior written permission.
%% 
%% THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
%% "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
%% LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
%% FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
%% COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
%% INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
%% BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
%% LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
%% CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
%% LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
%% ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
%% POSSIBILITY OF SUCH DAMAGE.
-module(ewpcap).
-include("ewpcap.hrl").

-export([
    open/0, open/1, open/2,
    close/1,
    filter/2, filter/3,
    read/1, read/2,
    write/2,
    getifaddrs/0, dev/0
    ]).

-define(PCAP_NETMASK_UNKNOWN, 16#ffffffff).
-define(DLT_EN10MB, 1).


-on_load(on_load/0).

%%--------------------------------------------------------------------
%%% NIF stubs
%%--------------------------------------------------------------------
on_load() ->
    case erlang:system_info(smp_support) of
        true ->
            erlang:load_nif(progname(), []);
        false ->
            {error, "Requires smp support (-smp enable)"}
        end.

pcap_compile(_,_,_,_) ->
    erlang:nif_error(not_implemented).

pcap_open_live(_,_,_,_) ->
    erlang:nif_error(not_implemented).

pcap_close(_) ->
    erlang:nif_error(not_implemented).

pcap_lookupdev() ->
    erlang:nif_error(not_implemented).

pcap_findalldevs() ->
    erlang:nif_error(not_implemented).

pcap_loop(_) ->
    erlang:nif_error(not_implemented).

pcap_sendpacket(_,_) ->
    erlang:nif_error(not_implemented).


%%--------------------------------------------------------------------
%%% API
%%--------------------------------------------------------------------
open() ->
    open(<<>>, []).
open(Dev) ->
    open(Dev, []).
open(<<>>, Options) ->
    {ok, Dev} = pcap_lookupdev(),
    open(Dev, Options);
open(Dev, Options) when is_list(Options) ->
    Snaplen = proplists:get_value(snaplen, Options, 16#ffff),
    Promisc = bool(proplists:get_value(promisc, Options, false)),
    To_ms = proplists:get_value(to_ms, Options, 500),
    Filter = proplists:get_value(filter, Options, <<>>),

    case pcap_open_live(Dev, Snaplen, Promisc, To_ms) of
        {ok, Socket} ->
            open_1(Socket, Options, Filter);
        Error ->
            Error
    end.

open_1(Socket, _Options, <<>>) ->
    open_2(Socket);
open_1(Socket, Options, Filter) ->
    case filter(Socket, Filter, Options) of
        ok ->
            open_2(Socket);
        Error ->
            Error
    end.

open_2(Socket) ->
    case loop(Socket) of
        ok -> {ok, Socket};
        Error -> Error
    end.

close(#ewpcap_resource{res = Res}) ->
    pcap_close(Res).

filter(Res, Filter) ->
    filter(Res, Filter, []).

filter(#ewpcap_resource{res = Res}, Filter, Options) when is_binary(Filter); is_list(Filter) ->
    Optimize = bool(proplists:get_value(optimize, Options, true)),
    Netmask = mask(proplists:get_value(netmask, Options, ?PCAP_NETMASK_UNKNOWN)),

    pcap_compile(Res, Filter, Optimize, Netmask).

loop(#ewpcap_resource{res = Res}) ->
    pcap_loop(Res).

read(Res) ->
    read(Res, infinity).
read(#ewpcap_resource{ref = Ref}, Timeout) ->
    receive
        {ewpcap, Ref, _DatalinkType, _Time, _ActualLength, Packet} ->
            {ok, Packet};
        {ewpcap_error, Ref, Error} ->
            {error, Error}
    after
        Timeout -> {error, eagain}
    end.

write(#ewpcap_resource{res = Res}, Data) when is_list(Data); is_binary(Data) ->
    pcap_sendpacket(Res, Data).

dev() ->
    pcap_lookupdev().

getifaddrs() ->
    case pcap_findalldevs() of
        {ok, Iflist} ->
            {ok, [ iface(N) || N <- lists:reverse(Iflist) ]};
        Error ->
            Error
    end.

iface({If, Attr}) ->
    {If, addr(Attr)}.

addr(Attr) ->
    addr(Attr, []).
addr([], Attr) ->
    Attr;
addr([{Key, <<A,B,C,D>>}|T], Attr) ->
    addr(T, [{Key, {A,B,C,D}}|Attr]);
addr([{Key, <<A:16,B:16,C:16,D:16,E:16,F:16,G:16,H:16>>}|T], Attr) ->
    addr(T, [{Key, {A,B,C,D,E,F,G,H}}|Attr]);
addr([N|T], Attr) ->
    addr(T, [N|Attr]).

%%--------------------------------------------------------------------
%%% Internal functions
%%--------------------------------------------------------------------
bool(true) -> 1;
bool(false) -> 0.

mask(N) when is_integer(N) -> N;
mask({A,B,C,D}) -> (A bsl 24) bor (B bsl 16) bor (C bsl 8) bor D.

progname() ->
    case code:priv_dir(?MODULE) of
        {error,bad_name} ->
            filename:join([
                filename:dirname(code:which(?MODULE)),
                    "..",
                    "priv",
                    ?MODULE
                ]);
        Dir ->
            filename:join([Dir,?MODULE])
    end.
