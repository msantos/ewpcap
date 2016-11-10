%% Copyright (c) 2012-2016, Michael Santos <michael.santos@gmail.com>
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
-module(ewpcap_SUITE).

-include_lib("common_test/include/ct.hrl").
-include("ewpcap.hrl").

-export([
        all/0,
        groups/0
    ]).

-export([
        sniff/1,
        getifaddrs/1,
        no_tests/1
    ]).


all() ->
    Priv = case ewpcap:getifaddrs() of
        {ok, []} ->
            nopriv;
        {ok, _Iflist} ->
            priv
    end,
    [{group, Priv}].

groups() ->
    [{priv, [], [sniff, getifaddrs]},
        {nopriv, [], [no_tests]}].

sniff(_Config) ->
    {ok, Ifname} = ewpcap:dev(),
    {ok, Socket} = ewpcap:open(Ifname, [{filter, "tcp and port 29"}|opt()]),

    {error, eagain} = ewpcap:read(Socket, 100),
    gen_tcp:connect({8,8,8,8}, 29, [binary], 100),
    {ok, Packet} = ewpcap:read(Socket),

    error_logger:info_report([{got, Packet}]),

    ok.

getifaddrs(_Config) ->
    case os:type() of
        {unix, _} ->
            {ok, Iflist1} = ewpcap:getifaddrs(),
            {ok, Iflist2} = inet:getifaddrs(),
            ifcmp(Iflist1, Iflist2);
        _ ->
            {skip, "results of ewpcap:getifaddrs/0 and inet:getifaddrs/0"
                   " may differ on this platorm"}
    end.

no_tests(_Config) ->
    {skip, "No tests"}.

ifcmp(Iflist1, Iflist2) ->
    % Get the common interfaces
    Ifs1 = sets:from_list(proplists:get_keys(Iflist1)),
    Ifs2 = sets:from_list(proplists:get_keys(Iflist2)),

    Ifs = sets:intersection(Ifs1, Ifs2),

    error_logger:info_report([{ifaces, sets:to_list(Ifs)}]),

    [ ifattr(Key, Ifs, Iflist1, Iflist2) ||
        Key <- [addr, netmask, broadaddr, dstaddr] ].

ifattr(Key, Ifs, Iflist1, Iflist2) ->
    [ begin
            R = if_value(Key, Ifname, Iflist1),
            R = if_value(Key, Ifname, Iflist2)
        end || Ifname <- sets:to_list(Ifs) ].

% Assumes sorting is the same
if_value(Key, Ifname, Ifattr) ->
    Attr = proplists:get_value(Ifname, Ifattr),
    proplists:get_all_values(Key, Attr).

opt() ->
    case os:type() of
        {unix, sunos} -> [promisc];
        _ -> []
    end.
