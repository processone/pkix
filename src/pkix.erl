%%%-------------------------------------------------------------------
%%% Created : 22 Sep 2018 by Evgeny Khramtsov <ekhramtsov@process-one.net>
%%%
%%% Copyright (C) 2002-2018 ProcessOne, SARL. All Rights Reserved.
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
-module(pkix).
-behaviour(gen_server).

%% API
-export([start/0, stop/0, start_link/0]).
-export([add_file/1, del_file/1]).
-export([commit/1, commit/2]).
-export([get_certfile/0, get_certfile/1, get_certfiles/0, get_cafile/0]).
-export([format_error/1, is_pem_file/1]).
%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
	 terminate/2, code_change/3, format_status/2]).

-include_lib("public_key/include/public_key.hrl").
-include_lib("kernel/include/file.hrl").
-define(CALL_TIMEOUT, timer:minutes(10)).
-define(CERTFILE_TAB, pkix_certfiles).

-record(pem, {file :: binary(),
	      line :: pos_integer(),
	      data :: binary()}).
-record(state, {files = #{}      :: map(),
		certs = #{}      :: map(),
		keys  = #{}      :: map(),
		validate = false :: false | soft | hard,
		dir              :: undefined | binary(),
		cafile           :: undefined | binary()}).

-type state() :: #state{}.
-type commit_option() :: {cafile, file:filename_all()} |
			 {validate, false | soft | hard}.
-type filename() :: binary().
-type dirname() :: binary().
-type cert() :: #'OTPCertificate'{}.
-type priv_key() :: public_key:private_key().
-type cert_path() :: {path, [cert()]}.
-type cert_chain() :: {[cert()], priv_key()}.
-type pub_key() :: #'RSAPublicKey'{} | {integer(), #'Dss-Parms'{}} | #'ECPoint'{}.
-type bad_cert_reason() :: missing_priv_key | bad_der | bad_pem | empty |
			   encrypted | unknown_key_algo | unknown_key_type.
-type invalid_cert_reason() :: cert_expired | invalid_issuer | invalid_signature |
			       name_not_permitted | missing_basic_constraint |
			       invalid_key_usage | selfsigned_peer | unknown_ca.
-type bad_cert_error() :: {bad_cert, pos_integer(), bad_cert_reason()}.
-type invalid_cert_error() :: {invalid_cert, pos_integer(), invalid_cert_reason()}.
-type io_error() :: file:posix().
-export_type([bad_cert_error/0, invalid_cert_error/0, io_error/0]).

%%%===================================================================
%%% API
%%%===================================================================
-spec start() -> ok | {error, term()}.
start() ->
    case application:ensure_all_started(?MODULE) of
	{ok, _} -> ok;
	{error, _} = Err -> Err
    end.

-spec stop() -> ok | {error, term()}.
stop() ->
    application:stop(?MODULE).

-spec start_link() -> {ok, Pid :: pid()} |
		      {error, Error :: {already_started, pid()}} |
		      {error, Error :: term()} |
		      ignore.
start_link() ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).

-spec add_file(file:filename_all()) -> ok | {error, bad_cert_error() | io_error()}.
add_file(Path) ->
    gen_server:call(?MODULE, {add_file, prep_path(Path)}, ?CALL_TIMEOUT).

-spec del_file(file:filename_all()) -> ok.
del_file(Path) ->
    gen_server:call(?MODULE, {del_file, prep_path(Path)}, ?CALL_TIMEOUT).

-spec is_pem_file(file:filename_all()) -> true | {false, bad_cert_error() | io_error()}.
is_pem_file(Path) ->
    case pem_decode_file(prep_path(Path)) of
	{ok, _, _} -> true;
	{error, Why} -> {false, Why}
    end.

-spec commit(file:dirname_all()) ->
      {ok, Errors :: [{filename(), bad_cert_error() | invalid_cert_error() | io_error()}],
           Warnings :: [{filename(), bad_cert_error() | invalid_cert_error()}],
           CAError :: {filename(), bad_cert_error() | io_error()} | undefined} |
      {error, filename() | dirname(), io_error()}.
commit(Dir) ->
    commit(Dir, []).

-spec commit(file:dirname_all(), [commit_option()]) ->
      {ok, Errors :: [{filename(), bad_cert_error() | invalid_cert_error() | io_error()}],
           Warnings :: [{filename(), bad_cert_error() | invalid_cert_error()}],
           CAError :: {filename(), bad_cert_error() | io_error()} | undefined} |
      {error, filename() | dirname(), io_error()}.
commit(Dir, Opts) ->
    Validate = proplists:get_value(validate, Opts, soft),
    CAFile = case proplists:get_value(cafile, Opts) of
		 undefined -> get_cafile();
		 Path -> prep_path(Path)
	     end,
    gen_server:call(?MODULE, {commit, prep_path(Dir), CAFile, Validate}, ?CALL_TIMEOUT).

-spec get_certfile() -> {EC  :: filename() | undefined,
			 RSA :: filename() | undefined,
			 DSA :: filename() | undefined} | error.
get_certfile() ->
    case ets:first(?CERTFILE_TAB) of
	'$end_of_table' -> error;
	Domain ->
	    try ets:lookup_element(?CERTFILE_TAB, Domain, 2)
	    catch _:badarg -> error
	    end
    end.

-spec get_certfile(binary()) -> {EC  :: filename() | undefined,
				 RSA :: filename() | undefined,
				 DSA :: filename() | undefined} | error.
get_certfile(Domain) ->
    try ets:lookup_element(?CERTFILE_TAB, Domain, 2)
    catch _:badarg ->
	    GlobDomain = re:replace(Domain, "^[^\\.]+", "*", [{return, binary}]),
	    try ets:lookup_element(?CERTFILE_TAB, GlobDomain, 2)
	    catch _:badarg -> error
	    end
    end.

-spec get_certfiles() -> [{binary(), [{filename(), ec | rsa | dsa}]}].
get_certfiles() ->
    ets:tab2list(?CERTFILE_TAB).

-spec get_cafile() -> filename().
get_cafile() ->
    get_cafile(possible_cafile_locations()).

-spec format_error(bad_cert_error() | invalid_cert_error() | io_error()) -> string().
format_error({bad_cert, _Line, empty}) ->
    "no supported PEM encoded entries found";
format_error({bad_cert, Line, bad_pem}) ->
    at_line(Line, "failed to decode from PEM format");
format_error({bad_cert, Line, bad_der}) ->
    at_line(Line, "failed to decode from DER format");
format_error({bad_cert, Line, encrypted}) ->
    at_line(Line, "encrypted certificate");
format_error({bad_cert, Line, unknown_key_algo}) ->
    at_line(Line, "unknown private key algorithm");
format_error({bad_cert, Line, unknown_key_type}) ->
    at_line(Line, "private key is of unknown type");
format_error({bad_cert, Line, missing_priv_key}) ->
    at_line(Line, "no matching private key found for this certificate");
format_error({invalid_cert, Line, cert_expired}) ->
    at_line(Line, "certificate is no longer valid as its expiration date has passed");
format_error({invalid_cert, Line, invalid_issuer}) ->
    at_line(Line, "certificate issuer name does not match the name of the "
	          "issuer certificate");
format_error({invalid_cert, Line, invalid_signature}) ->
    at_line(Line, "certificate was not signed by its issuer certificate");
format_error({invalid_cert, Line, name_not_permitted}) ->
    at_line(Line, "invalid Subject Alternative Name extension");
format_error({invalid_cert, Line, missing_basic_constraint}) ->
    at_line(Line, "certificate, required to have the basic constraints extension, "
	          "does not have a basic constraints extension");
format_error({invalid_cert, Line, invalid_key_usage}) ->
    at_line(Line, "certificate key is used in an invalid way according "
	          "to the key-usage extension");
format_error({invalid_cert, Line, selfsigned_peer}) ->
    at_line(Line, "self-signed certificate");
format_error({invalid_cert, Line, unknown_ca}) ->
    at_line(Line, "certificate is signed by unknown CA");
format_error({invalid_cert, Line, Unknown}) ->
    at_line(Line, io_lib:format("~w", [Unknown]));
format_error(Posix) when is_atom(Posix) ->
    case file:format_error(Posix) of
	"unknown POSIX error" ->
	    atom_to_list(Posix);
	Reason ->
	    Reason
    end;
format_error(Reason) ->
    lists:flatten(io_lib:format("unexpected error: ~w", [Reason])).

%%%===================================================================
%%% gen_server callbacks
%%%===================================================================
-spec init([]) -> {ok, state()}.
init([]) ->
    process_flag(trap_exit, true),
    ets:new(?CERTFILE_TAB, [named_table, public, {read_concurrency, true}]),
    {ok, #state{}}.

-spec handle_call({add_file, filename()} |
		  {del_file, filename()} |
		  {commit, dirname(), filename(), false | soft | hard} |
		  term(), term(), state()) ->
			 {reply, term(), state()} | {noreply, state()}.
handle_call({add_file, Path}, _, State) ->
    case add_file(Path, State) of
	{ok, State1} -> {reply, ok, State1};
	{error, _} = Err -> {reply, Err, State}
    end;
handle_call({del_file, Path}, _, State) ->
    State1 = del_file(Path, State),
    {reply, ok, State1};
handle_call({commit, Dir, CAFile, Validate}, _From, State) ->
    {BadCerts, State1} = reload_files(State),
    case commit(State1, Dir, CAFile, Validate) of
	{ok, CertErrors, CertWarns, CAError} ->
	    State2 = State1#state{dir = Dir,
				  cafile = CAFile,
				  validate = Validate},
	    {reply, {ok, BadCerts ++ CertErrors, CertWarns, CAError}, State2};
	{error, _, _} = Err ->
	    {reply, Err, State}
    end;
handle_call(Request, _From, State) ->
    error_logger:warning_msg("Unexpected call: ~p", [Request]),
    {noreply, State}.

-spec handle_cast(term(), state()) -> {noreply, state()}.
handle_cast(Msg, State) ->
    error_logger:warning_msg("Unexpected cast: ~p", [Msg]),
    {noreply, State}.

-spec handle_info(term(), state()) -> {noreply, state()}.
handle_info(Info, State) ->
    error_logger:warning_msg("Unexpected info: ~p", [Info]),
    {noreply, State}.

-spec terminate(normal | shutdown | {shutdown, term()} | term(), state()) -> any().
terminate(_Reason, State) ->
    case State#state.dir of
	undefined -> ok;
	Dir -> clear_dir(Dir, [])
    end.

-spec code_change(term() | {down, term()}, state(), term()) -> {ok, state()}.
code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

-spec format_status(normal | terminate, list()) -> term().
format_status(_Opt, Status) ->
    Status.

%%%===================================================================
%%% Certificate file loading/unloading
%%%===================================================================
-spec add_file(filename(), state()) ->
	       {ok, state()} | {error, bad_cert_error() | io_error()}.
add_file(File, State) ->
    case mtime(File) of
	{ok, MTime} ->
	    case maps:get(File, State#state.files, 0) of
		Time when MTime =< Time ->
		    {ok, State};
		_ ->
		    case pem_decode_file(File) of
			{ok, Certs, Keys} ->
			    NewCerts = maps:merge(State#state.certs, Certs),
			    NewKeys = maps:merge(State#state.keys, Keys),
			    NewFiles = maps:put(File, MTime, State#state.files),
			    {ok, State#state{files = NewFiles,
					     certs = NewCerts,
					     keys = NewKeys}};
			{error, _} = Err ->
			    Err
		    end
	    end;
	{error, _} = Err ->
	    Err
    end.

-spec del_file(filename(), state()) -> state().
del_file(File, State) ->
    Filter = fun(_, #pem{file = F}) -> F /= File end,
    NewFiles = maps:remove(File, State#state.files),
    NewCerts = maps:filter(Filter, State#state.certs),
    NewKeys = maps:filter(Filter, State#state.keys),
    State#state{files = NewFiles, certs = NewCerts, keys = NewKeys}.

-spec reload_files(state()) -> {[{filename(), bad_cert_error() | io_error()}],
				state()}.
reload_files(State) ->
    Files = maps:keys(State#state.files),
    {Errs, State1} = lists:mapfoldl(
		       fun(File, Acc) ->
			       case add_file(File, Acc) of
				   {ok, Acc1} ->
				       {[], Acc1};
				   {error, Why} ->
				       Acc1 = del_file(File, Acc),
				       {[{File, Why}], Acc1}
			       end
		       end, State, Files),
    {lists:flatten(Errs), State1}.

%%%===================================================================
%%% Certificate file decoding
%%%===================================================================
-spec pem_decode_file(filename()) -> {ok, map(), map()} |
				     {error, bad_cert_error() | io_error()}.
pem_decode_file(Path) ->
    case file:open(Path, [read, raw, read_ahead, binary]) of
	{ok, Fd} ->
	    case pem_decode(Fd, 1, []) of
		{ok, PEMs} ->
		    pem_decode_entries(PEMs, Path, #{}, #{});
		{error, _} = Err ->
		    Err
	    end;
	{error, _} = Err ->
	    Err
    end.

-spec pem_decode(file:fd(), pos_integer(), [{pos_integer(), binary()}]) ->
			{ok, [{pos_integer(), binary()}]} | {error, io_error()}.
pem_decode(Fd, Line, PEMs) ->
    case pem_decode(Fd, Line, 0, []) of
	{ok, NewLine, PEM} ->
	    pem_decode(Fd, NewLine, [PEM|PEMs]);
	eof ->
	    {ok, lists:reverse(PEMs)};
	{error, _} = Err ->
	    Err
    end.

-spec pem_decode(file:fd(), pos_integer(), non_neg_integer(), [binary()]) ->
      {ok, pos_integer(), {pos_integer(), binary()}} | {error, io_error()} | eof.
pem_decode(Fd, Line, 0, []) ->
    case file:read_line(Fd) of
	{ok, <<"-----BEGIN ", _/binary>> = Data} ->
	    pem_decode(Fd, Line+1, Line, [Data]);
	{ok, _} ->
	    pem_decode(Fd, Line+1, 0, []);
	Err ->
	    Err
    end;
pem_decode(Fd, Line, Begin, Buf) ->
    case file:read_line(Fd) of
	{ok, <<"-----END ", _/binary>> = Data} ->
	    PEM = list_to_binary(lists:reverse([Data|Buf])),
	    {ok, Line+1, {Begin, PEM}};
	{ok, Data} ->
	    pem_decode(Fd, Line+1, Begin, [Data|Buf]);
	Err ->
	    Err
    end.

-spec pem_decode_entries([{pos_integer(), binary()}], filename(),
			 map(), map()) -> {ok, map(), map()} | {error, bad_cert_error()}.
pem_decode_entries([{Begin, Data}|PEMs], File, Certs, PrivKeys) ->
    P = #pem{file = File, line = Begin, data = Data},
    try public_key:pem_decode(Data) of
	[PemEntry] ->
	    try der_decode(PemEntry) of
		undefined ->
		    pem_decode_entries(PEMs, File, Certs, PrivKeys);
		#'OTPCertificate'{} = Cert ->
		    pem_decode_entries(PEMs, File, Certs#{Cert => P}, PrivKeys);
		PrivKey ->
		    pem_decode_entries(PEMs, File, Certs, PrivKeys#{PrivKey => P})
	    catch _:{bad_cert, Why} ->
		    {error, {bad_cert, Begin, Why}};
		  _:_ ->
		    {error, {bad_cert, Begin, bad_der}}
	    end
    catch _:_ ->
	    {error, {bad_cert, Begin, bad_pem}}
    end;
pem_decode_entries([], _File, Certs, PrivKeys) ->
    case maps:size(Certs) + maps:size(PrivKeys) of
	0 -> {error, {bad_cert, 1, empty}};
	_ -> {ok, Certs, PrivKeys}
    end.

-spec der_decode(public_key:pem_entry()) -> cert() | priv_key() | undefined.
der_decode({_, _, Flag}) when Flag /= not_encrypted ->
    erlang:error({bad_cert, encrypted});
der_decode({'Certificate', Der, _}) ->
    public_key:pkix_decode_cert(Der, otp);
der_decode({'PrivateKeyInfo', Der, _}) ->
    case public_key:der_decode('PrivateKeyInfo', Der) of
	#'PrivateKeyInfo'{privateKeyAlgorithm =
			      #'PrivateKeyInfo_privateKeyAlgorithm'{
				 algorithm = Algo},
			  privateKey = Key} ->
	    KeyBin = iolist_to_binary(Key),
	    case Algo of
		?'rsaEncryption' ->
		    public_key:der_decode('RSAPrivateKey', KeyBin);
		?'id-dsa' ->
		    public_key:der_decode('DSAPrivateKey', KeyBin);
		?'id-ecPublicKey' ->
		    public_key:der_decode('ECPrivateKey', KeyBin);
		_ ->
		    erlang:error({bad_cert, unknown_key_algo})
	    end;
	#'RSAPrivateKey'{} = Key -> Key;
	#'DSAPrivateKey'{} = Key -> Key;
	#'ECPrivateKey'{} = Key -> Key;
	_ -> erlang:error({bad_cert, unknown_key_type})
    end;
der_decode({Tag, Der, _}) when Tag == 'RSAPrivateKey';
			       Tag == 'DSAPrivateKey';
			       Tag == 'ECPrivateKey' ->
    public_key:der_decode(Tag, Der);
der_decode({_, _, _}) ->
    undefined.

%%%===================================================================
%%% Certificate chains processing
%%%===================================================================
-spec commit(state(), dirname(), filename(), false | soft | hard) ->
	     {ok, [{filename(), bad_cert_error() | invalid_cert_error()}],
	          [{filename(), invalid_cert_error()}],
	          {filename(), bad_cert_error() | io_error()} | undefined} |
	     {error, filename() | dirname(), io_error()}.
commit(State, Dir, CAFile, ValidateHow) ->
    {Chains, BadCertsWithReason} = build_chains(State),
    {CAError, InvalidCertsWithReason} = validate(Chains, CAFile, ValidateHow),
    InvalidCerts = [C || {C, _} <- InvalidCertsWithReason],
    ValidChains = drop_invalid_chains(Chains, InvalidCerts),
    SortedChains = case ValidateHow of
		       hard when CAError == undefined ->
			   ValidChains = drop_invalid_chains(Chains, InvalidCerts),
			   sort_chains(ValidChains, []);
		       hard -> [];
		       _ -> sort_chains(Chains, InvalidCerts)
		   end,
    case store_chains(SortedChains, Dir, State) of
	ok ->
	    Bad = map_errors(State, bad_cert, BadCertsWithReason),
	    Invalid = map_errors(State, invalid_cert, InvalidCertsWithReason),
	    case ValidateHow of
		hard ->
		    {ok, Bad ++ Invalid, [], CAError};
		_ ->
		    {ok, Bad, Invalid, CAError}
	    end;
	{error, _, _} = Err ->
	    Err
    end.

-spec build_chains(state()) -> {[cert_chain()], [{cert(), bad_cert_reason()}]}.
build_chains(State) ->
    CertPaths = get_cert_paths(maps:keys(State#state.certs)),
    match_cert_keys(CertPaths, maps:keys(State#state.keys)).

-spec match_cert_keys([cert_path()], [priv_key()]) ->
		      {[cert_chain()], [{cert(), bad_cert_reason()}]}.
match_cert_keys(CertPaths, PrivKeys) ->
    KeyPairs = [{pubkey_from_privkey(PrivKey), PrivKey} || PrivKey <- PrivKeys],
    match_cert_keys(CertPaths, KeyPairs, [], []).

-spec match_cert_keys([cert_path()], [{pub_key(), priv_key()}],
		      [cert_chain()], [{cert(), bad_cert_reason()}]) ->
			     {[cert_chain()], [{cert(), bad_cert_reason()}]}.
match_cert_keys([{path, Certs}|CertPaths], KeyPairs, Chains, BadCerts) ->
    [Cert|_] = RevCerts = lists:reverse(Certs),
    PubKey = pubkey_from_cert(Cert),
    case lists:keyfind(PubKey, 1, KeyPairs) of
	false ->
	    match_cert_keys(CertPaths, KeyPairs, Chains,
			    [{Cert, missing_priv_key}|BadCerts]);
	{_, PrivKey} ->
	    match_cert_keys(CertPaths, KeyPairs,
			    [{RevCerts, PrivKey}|Chains], BadCerts)
    end;
match_cert_keys([], _, Chains, BadCerts) ->
    {Chains, BadCerts}.

-spec pubkey_from_cert(cert()) -> pub_key().
pubkey_from_cert(Cert) ->
    TBSCert = Cert#'OTPCertificate'.tbsCertificate,
    PubKeyInfo = TBSCert#'OTPTBSCertificate'.subjectPublicKeyInfo,
    SubjPubKey = PubKeyInfo#'OTPSubjectPublicKeyInfo'.subjectPublicKey,
    case PubKeyInfo#'OTPSubjectPublicKeyInfo'.algorithm of
	#'PublicKeyAlgorithm'{
	   algorithm = ?rsaEncryption} ->
	    SubjPubKey;
	#'PublicKeyAlgorithm'{
	   algorithm = ?'id-dsa',
	   parameters = {params, DSSParams}} ->
	    {SubjPubKey, DSSParams};
	#'PublicKeyAlgorithm'{
	   algorithm = ?'id-ecPublicKey'} ->
	    SubjPubKey
    end.

-spec pubkey_from_privkey(priv_key()) -> pub_key().
pubkey_from_privkey(#'RSAPrivateKey'{modulus = Modulus,
				     publicExponent = Exp}) ->
    #'RSAPublicKey'{modulus = Modulus,
		    publicExponent = Exp};
pubkey_from_privkey(#'DSAPrivateKey'{p = P, q = Q, g = G, y = Y}) ->
    {Y, #'Dss-Parms'{p = P, q = Q, g = G}};
pubkey_from_privkey(#'ECPrivateKey'{publicKey = Key}) ->
    #'ECPoint'{point = Key}.

-spec cert_type(priv_key()) -> ec | rsa | dsa.
cert_type(#'ECPrivateKey'{}) -> ec;
cert_type(#'RSAPrivateKey'{}) -> rsa;
cert_type(#'DSAPrivateKey'{}) -> dsa.

-spec drop_invalid_chains([cert_chain()], [cert()]) -> [cert_chain()].
drop_invalid_chains(Chains, InvalidCerts) ->
    lists:filter(
      fun({[Cert|_], _}) ->
	      not lists:member(Cert, InvalidCerts)
      end, Chains).

-spec sort_chains([cert_chain()], [cert()]) -> [cert_chain()].
sort_chains(Chains, InvalidCerts) ->
    lists:sort(
      fun({[Cert1|_], _}, {[Cert2|_], _}) ->
	      IsValid1 = not lists:member(Cert1, InvalidCerts),
	      IsValid2 = not lists:member(Cert2, InvalidCerts),
	      if IsValid1 and not IsValid2 ->
		      false;
		 IsValid2 and not IsValid1 ->
		      true;
		 true ->
		      compare_expiration_date(Cert1, Cert2)
	      end
      end, Chains).

-spec map_errors(state(), bad_cert | invalid_cert,
		 [{cert(), bad_cert_reason() | invalid_cert_reason()}]) ->
			[{filename(), bad_cert_error() | invalid_cert_error()}].
map_errors(State, Type, CertsWithReason) ->
    lists:map(
      fun({Cert, Reason}) ->
	      #pem{file = File, line = Line} =
		  maps:get(Cert, State#state.certs),
	      {File, {Type, Line, Reason}}
      end, CertsWithReason).

%%%===================================================================
%%% Certificates storage
%%%===================================================================
-spec store_chains([cert_chain()], dirname(), state()) ->
			 ok | {error, filename() | dirname(), io_error()}.
store_chains(Chains, Dir, State) ->
    case State#state.dir of
	undefined ->
	    case filelib:ensure_dir(filename:join(Dir, "foo")) of
		ok ->
		    clear_dir(Dir, []),
		    store_chains(Chains, Dir, State, #{});
		{error, Why} ->
		    {error, Dir, Why}
	    end;
	_ ->
	    store_chains(Chains, Dir, State, #{})
    end.

-spec store_chains([cert_chain()], dirname(), state(), map()) ->
			  ok | {error, filename(), io_error()}.
store_chains([{Certs, PrivKey} = Chain|Chains], Dir, State, Doms) ->
    case store_chain(Chain, Dir, State) of
	{ok, File} ->
	    Cert = hd(Certs),
	    Type = cert_type(PrivKey),
	    File1 = unicode:characters_to_binary(File),
	    Doms1 = case extract_domains(Cert) of
			[] ->
			    Files = maps:get(<<>>, Doms, []),
			    Doms#{<<>> => [{Type, File1}|Files]};
			Domains ->
			    lists:foldl(
			      fun(Domain, Acc) ->
				      Files = maps:get(Domain, Acc, []),
				      Acc#{Domain => [{Type, File1}|Files]}
			      end, Doms, Domains)
		    end,
	    store_chains(Chains, Dir, State, Doms1);
	{error, _, _} = Err ->
	    Err
    end;
store_chains([], Dir, _State, Doms) ->
    Old = ets:tab2list(?CERTFILE_TAB),
    New = maps:fold(
	    fun(Domain, Files, Acc) ->
		    [{Domain, {proplists:get_value(ec, Files),
			       proplists:get_value(rsa, Files),
			       proplists:get_value(dsa, Files)}}|Acc]
	    end, [], Doms),
    ets:insert(?CERTFILE_TAB, New),
    lists:foreach(
      fun(Elem) ->
	      ets:delete_object(?CERTFILE_TAB, Elem)
      end, Old -- New),
    NewFiles = lists:flatmap(
		 fun({_, T}) ->
			 [F || F <- tuple_to_list(T), F /= undefined]
		 end, New),
    clear_dir(Dir, NewFiles).

-spec store_chain(cert_chain(), dirname(), state()) ->
			 {ok, filename()} | {error, filename(), io_error()}.
store_chain({Certs, Key}, Dir, State) ->
    PEM1 = pem_encode(Certs, State#state.certs),
    PEM2 = pem_encode([Key], State#state.keys),
    Data = iolist_to_binary([PEM1, PEM2]),
    FileName = filename:join(Dir, sha1(Data)),
    case file:write_file(FileName, Data) of
	ok ->
	    case file:change_mode(FileName, 8#600) of
		ok -> ok;
		{error, Why} ->
		    error_logger:warning_msg(
		      "Failed to change permissions of ~s: ~s",
		      [FileName, file:format_error(Why)])
	    end,
	    {ok, FileName};
	{error, Why} ->
	    {error, FileName, Why}
    end.

-spec pem_encode([cert()] | [priv_key()], map()) -> iolist().
pem_encode(Objs, Map) ->
    lists:map(
      fun(Obj) ->
	      #pem{file = File, line = Line, data = PEM} = maps:get(Obj, Map),
	      [io_lib:format("From ~s:~B~n", [File, Line]), PEM]
      end, Objs).

%%%===================================================================
%%% Domains extraction
%%%===================================================================
-spec extract_domains(cert()) -> [binary()].
extract_domains(Cert) ->
    TBSCert = Cert#'OTPCertificate'.tbsCertificate,
    {rdnSequence, Subject} = TBSCert#'OTPTBSCertificate'.subject,
    Extensions = TBSCert#'OTPTBSCertificate'.extensions,
    get_domain_from_subject(lists:flatten(Subject)) ++
        get_domains_from_san(Extensions).

-spec get_domain_from_subject([#'AttributeTypeAndValue'{}]) -> [binary()].
get_domain_from_subject(AttrVals) ->
    case lists:keyfind(?'id-at-commonName',
                       #'AttributeTypeAndValue'.type,
                       AttrVals) of
        #'AttributeTypeAndValue'{value = {_, S}} ->
            [iolist_to_binary(S)];
        _ ->
            []
    end.

-spec get_domains_from_san([#'Extension'{}] | asn1_NOVALUE) -> [binary()].
get_domains_from_san(Extensions) when is_list(Extensions) ->
    case lists:keyfind(?'id-ce-subjectAltName',
                       #'Extension'.extnID,
                       Extensions) of
        #'Extension'{extnValue = Vals} ->
            lists:flatmap(
              fun({dNSName, S}) ->
                      [iolist_to_binary(S)];
                 (_) ->
                      []
              end, Vals);
        _ ->
            []
    end;
get_domains_from_san(_) ->
    [].

%%%===================================================================
%%% Certificates graph
%%%===================================================================
-spec get_cert_paths([cert()]) -> [cert_path()].
get_cert_paths(Certs) ->
    G = digraph:new([acyclic]),
    Paths = get_cert_paths(Certs, G),
    digraph:delete(G),
    Paths.

-spec get_cert_paths([cert()], digraph:graph()) -> [cert_path()].
get_cert_paths(Certs, G) ->
    lists:foreach(
      fun(Cert) ->
	      digraph:add_vertex(G, Cert)
      end, Certs),
    add_edges(G, Certs, Certs),
    lists:flatmap(
      fun(Cert) ->
	      case digraph:in_degree(G, Cert) of
		  0 ->
		      get_cert_path(G, [Cert]);
		  _ ->
		      []
	      end
      end, Certs).

add_edges(G, [Cert1|T], L) ->
    case public_key:pkix_is_self_signed(Cert1) of
	true ->
	    ok;
	false ->
	    lists:foreach(
	      fun(Cert2) when Cert1 /= Cert2 ->
		      case public_key:pkix_is_issuer(Cert1, Cert2) of
			  true ->
			      digraph:add_edge(G, Cert1, Cert2);
			  false ->
			      ok
		      end;
		 (_) ->
		      ok
	      end, L)
    end,
    add_edges(G, T, L);
add_edges(_, [], _) ->
    ok.

get_cert_path(G, [Root|_] = Acc) ->
    case digraph:out_edges(G, Root) of
	[] ->
	    [{path, Acc}];
	Es ->
	    lists:flatmap(
	      fun(E) ->
		      {_, _, V, _} = digraph:edge(G, E),
		      get_cert_path(G, [V|Acc])
	      end, Es)
    end.

%%%===================================================================
%%% Certificates chain validation
%%%===================================================================
-spec validate([cert_chain()], filename(), false | soft | hard) ->
	       {undefined | {filename(), bad_cert_error() | io_error()},
		[{cert(), invalid_cert_reason()}]}.
validate(_Chains, _CAFile, false) ->
    {undefined, []};
validate(Chains, CAFile, _) ->
    {CAError, IssuerCerts} = case pem_decode_file(CAFile) of
				 {error, Why} ->
				     {{CAFile, Why}, []};
				 {ok, Ret, _} ->
				     {undefined, maps:keys(Ret)}
			     end,
    {CAError,
     lists:filtermap(
       fun({Certs, _PrivKey}) ->
	       RevCerts = lists:reverse(Certs),
	       case validate_path(RevCerts, IssuerCerts) of
		   ok ->
		       false;
		   {error, Reason} ->
		       {true, {hd(RevCerts), Reason}}
	       end
       end, Chains)}.

-spec validate_path([cert()], [cert()]) -> ok | {error, invalid_cert_reason()}.
validate_path([Cert|_] = Certs, IssuerCerts) ->
    case find_issuer_cert(Cert, IssuerCerts) of
	{ok, IssuerCert} ->
	    case public_key:pkix_path_validation(IssuerCert, Certs, []) of
		{ok, _} ->
		    ok;
		{error, _} = Err ->
		    Err
	    end;
	error ->
	    case public_key:pkix_is_self_signed(Cert) of
		true ->
		    {error, selfsigned_peer};
		false ->
		    {error, unknown_ca}
	    end
    end.

-spec find_issuer_cert(cert(), [cert()]) -> {ok, cert()} | error.
find_issuer_cert(Cert, [IssuerCert|IssuerCerts]) ->
    case public_key:pkix_is_issuer(Cert, IssuerCert) of
	true -> {ok, IssuerCert};
	false -> find_issuer_cert(Cert, IssuerCerts)
    end;
find_issuer_cert(_Cert, []) ->
    error.

%%%===================================================================
%%% Defaults
%%%===================================================================
-spec get_cafile([filename()]) -> filename().
get_cafile([File|Files]) ->
    case filelib:is_regular(File) of
	true -> File;
	false -> get_cafile(Files)
    end;
get_cafile([]) ->
    Dir = case code:priv_dir(?MODULE) of
	      {error, _} -> "priv";
	      Path -> Path
	  end,
    prep_path(filename:join(Dir, "cacert.pem")).

-spec possible_cafile_locations() -> [filename()].
possible_cafile_locations() ->
    %% TODO: add OSX/Darwin CA bundle path
    [<<"/etc/ssl/certs/ca-certificates.crt">>,                %% Debian/Ubuntu/Gentoo etc.
     <<"/etc/pki/tls/certs/ca-bundle.crt">>,                  %% Fedora/RHEL 6
     <<"/etc/ssl/ca-bundle.pem">>,                            %% OpenSUSE
     <<"/etc/pki/tls/cacert.pem">>,                           %% OpenELEC
     <<"/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem">>, %% CentOS/RHEL 7
     <<"/usr/local/etc/ssl/cert.pem">>,                       %% FreeBSD
     <<"/etc/ssl/cert.pem">>,                                 %% OpenBSD
     <<"/usr/local/share/certs/ca-root-nss.crt">>,            %% DragonFly
     <<"/etc/openssl/certs/ca-certificates.crt">>,            %% NetBSD
     <<"/etc/certs/ca-certificates.crt">>,                    %% Solaris 11.2+
     <<"/etc/ssl/cacert.pem">>,                               %% OmniOS
     <<"/sys/lib/tls/ca.pem">>].                              %% Plan9

%%%===================================================================
%%% Auxiliary functions
%%%===================================================================
-spec prep_path(file:filename_all()) -> filename().
prep_path(Path0) ->
    case filename:pathtype(Path0) of
	relative ->
	    case file:get_cwd() of
		{ok, CWD} ->
		    unicode:characters_to_binary(filename:join(CWD, Path0));
		{error, Reason} ->
		    error_logger:warning_msg(
		      "Failed to get current directory name: ~s",
		      [file:format_error(Reason)]),
		    unicode:characters_to_binary(Path0)
	    end;
	_ ->
	    unicode:characters_to_binary(Path0)
    end.

-spec get_timestamp({utcTime | generalTime, string()}) -> string().
get_timestamp({utcTime, [Y1,Y2|T]}) ->
    case list_to_integer([Y1,Y2]) of
        N when N >= 50 -> [$1,$9,Y1,Y2|T];
	_ -> [$2,$0,Y1,Y2|T]
    end;
get_timestamp({generalTime, TS}) ->
    TS.

%% Returns true if the first certificate has sooner expiration date
-spec compare_expiration_date(cert(), cert()) -> boolean().
compare_expiration_date(#'OTPCertificate'{
			   tbsCertificate =
			       #'OTPTBSCertificate'{
				  validity = #'Validity'{notAfter = After1}}},
			#'OTPCertificate'{
			   tbsCertificate =
			       #'OTPTBSCertificate'{
				  validity = #'Validity'{notAfter = After2}}}) ->
    get_timestamp(After1) =< get_timestamp(After2).

-spec sha1(iodata()) -> binary().
sha1(Text) ->
    Bin = crypto:hash(sha, Text),
    to_hex(Bin).

-spec to_hex(binary()) -> binary().
to_hex(Bin) ->
    << <<(digit_to_xchar(N div 16)), (digit_to_xchar(N rem 16))>> || <<N>> <= Bin >>.

-spec digit_to_xchar(char()) -> char().
digit_to_xchar(D) when (D >= 0) and (D < 10) -> D + $0;
digit_to_xchar(D) -> D + $a - 10.

-spec at_line(pos_integer(), iolist()) -> string().
at_line(Line, List) ->
    lists:flatten(io_lib:format("at line ~B: ~s", [Line, List])).

-spec mtime(filename()) -> {ok, calendar:datetime() | undefined} |
			   {error, io_error()}.
mtime(File) ->
    case file:read_file_info(File) of
	{ok, #file_info{mtime = MTime}} -> {ok, MTime};
	{error, _} = Err -> Err
    end.

-spec clear_dir(dirname(), [filename()]) -> ok.
clear_dir(Dir, WhiteList) ->
    Files = filelib:fold_files(
	      binary_to_list(Dir), "^[a-f0-9]{40}$", false,
	      fun(File, Acc) ->
		      [unicode:characters_to_binary(File)|Acc]
	      end, []),
    lists:foreach(fun file:delete/1, Files -- WhiteList).
