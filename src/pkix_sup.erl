%%%-------------------------------------------------------------------
%%% Created : 22 Sep 2018 by Evgeny Khramtsov <ekhramtsov@process-one.net>
%%%
%%% Copyright (C) 2002-2020 ProcessOne, SARL. All Rights Reserved.
%%%
%%% Licensed under the Apache License, Version 2.0 (the "License");
%%% you may not use this file except in compliance with the License.
%%% You may obtain a copy of the License at
%%%
%%%     http://www.apache.org/licenses/LICENSE-2.0
%%%
%%% Unless required by applicable law or agreed to in writing, software
%%% distributed under the License is distributed on an "AS IS" BASIS,
%%% WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
%%% See the License for the specific language governing permissions and
%%% limitations under the License.
%%%
%%%-------------------------------------------------------------------
-module(pkix_sup).
-behaviour(supervisor).

%% API
-export([start_link/0]).
%% Supervisor callbacks
-export([init/1]).

-define(SHUTDOWN_TIMEOUT, timer:seconds(30)).

%%%===================================================================
%%% API functions
%%%===================================================================
-spec start_link() -> {ok, Pid :: pid()} |
		      {error, {already_started, Pid :: pid()}} |
		      {error, {shutdown, term()}} |
		      {error, term()} |
		      ignore.
start_link() ->
    supervisor:start_link({local, ?MODULE}, ?MODULE, []).

%%%===================================================================
%%% Supervisor callbacks
%%%===================================================================
-spec init([]) -> {ok, {supervisor:sup_flags(),	[supervisor:child_spec()]}}.
init([]) ->
    Spec = {pkix, {pkix, start_link, []}, permanent,
	    ?SHUTDOWN_TIMEOUT, worker, [pkix]},
    {ok, {{one_for_all, 10, 1}, [Spec]}}.

%%%===================================================================
%%% Internal functions
%%%===================================================================
