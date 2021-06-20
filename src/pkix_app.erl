%%%-------------------------------------------------------------------
%%% Created : 22 Sep 2018 by Evgeny Khramtsov <ekhramtsov@process-one.net>
%%%
%%% Copyright (C) 2002-2021 ProcessOne, SARL. All Rights Reserved.
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
-module(pkix_app).
-behaviour(application).

%% Application callbacks
-export([start/2, start_phase/3, stop/1, prep_stop/1,
	 config_change/3]).

%%%===================================================================
%%% Application callbacks
%%%===================================================================
-spec start(StartType :: normal |
			 {takeover, Node :: node()} |
			 {failover, Node :: node()},
	    StartArgs :: term()) ->
		   {ok, Pid :: pid()} |
		   {ok, Pid :: pid(), State :: term()} |
		   {error, Reason :: term()}.
start(_StartType, _StartArgs) ->
    pkix_sup:start_link().

-spec start_phase(Phase :: atom(),
		  StartType :: normal |
			       {takeover, Node :: node()} |
			       {failover, Node :: node()},
		  PhaseArgs :: term()) -> ok | {error, Reason :: term()}.
start_phase(_Phase, _StartType, _PhaseArgs) ->
    ok.

-spec stop(State :: term()) -> any().
stop(_State) ->
    ok.

-spec prep_stop(State :: term()) -> NewState :: term().
prep_stop(State) ->
    State.

-spec config_change(Changed :: [{Par :: atom(), Val :: term()}],
		    New :: [{Par :: atom(), Val :: term()}],
		    Removed :: [Par :: atom()]) -> ok.
config_change(_Changed, _New, _Removed) ->
    ok.

%%%===================================================================
%%% Internal functions
%%%===================================================================
