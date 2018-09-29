%%%-------------------------------------------------------------------
%%% Created : 26 Sep 2018 by Evgeny Khramtsov <ekhramtsov@process-one.net>
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
-module(pkix_test).
-include_lib("eunit/include/eunit.hrl").

-define(DSA_SELF_SIGNED, path("dsa-self-signed.pem")).
-define(RSA_SELF_SIGNED, path("rsa-self-signed.pem")).
-define(EC_SELF_SIGNED, path("ec-self-signed.pem")).

%%%===================================================================
%%% Tests
%%%===================================================================
start_test() ->
    ?assertEqual(ok, pkix:start()).

get_certfiles_test() ->
    ?assertEqual([], pkix:get_certfiles()).

non_existent_domain_certfile_test() ->
    ?assertEqual(error, pkix:get_certfile(<<"foo">>)),
    ?assertEqual(error, pkix:get_certfile(<<"bar.baz">>)).

commit_empty_test() ->
    commit_empty().

is_pem_file_test() ->
    {ok, Files} = file:list_dir(test_dir()),
    {Good, Bad} = lists:partition(
		    fun(Path) ->
			    case unicode:characters_to_list(
				   filename:basename(Path)) of
				"ca.pem" -> true;
				"ec-self-signed.pem" -> true;
				"no-domain.pem" -> true;
				"prime256v1-cert.pem" -> true;
				"prime256v1-key.pem" -> true;
				"dsa-cert.pem" -> true;
				"dsa-key.pem" -> true;
				"rsa-cert.pem" -> true;
				"rsa-key.pem" -> true;
				"dsa-self-signed.pem" -> true;
				"rsa-self-signed.pem" -> true;
				"secp384r1-cert.pem" -> true;
				"secp384r1-key.pem" -> true;
				"text-between.pem" -> true;
				"valid-cert.pem" -> true;
				"old.pem" -> true;
				"new.pem" -> true;
				_ -> false
			    end
		    end, Files),
    lists:foreach(
      fun(File) ->
	      ?assertEqual(true, pkix:is_pem_file(path(File)))
      end, Good),
    lists:foreach(
      fun(File) ->
	      ?assertMatch({false, _}, pkix:is_pem_file(path(File)))
      end, Bad).

add_del_dsa_key_test() ->
    File = path("dsa-key.pem"),
    ?assertEqual(ok, pkix:add_file(File)),
    ?assertEqual(ok, pkix:del_file(File)).

add_del_dsa_cert_test() ->
    File = path("dsa-cert.pem"),
    ?assertEqual(ok, pkix:add_file(File)),
    ?assertEqual(ok, pkix:del_file(File)).

add_del_rsa_key_test() ->
    File = path("rsa-key.pem"),
    ?assertEqual(ok, pkix:add_file(File)),
    ?assertEqual(ok, pkix:del_file(File)).

add_del_rsa_cert_test() ->
    File = path("rsa-cert.pem"),
    ?assertEqual(ok, pkix:add_file(File)),
    ?assertEqual(ok, pkix:del_file(File)).

add_del_ec_secp384r1_key_test() ->
    File = path("secp384r1-key.pem"),
    ?assertEqual(ok, pkix:add_file(File)),
    ?assertEqual(ok, pkix:del_file(File)).

add_del_ec_prime256v1_key_test() ->
    File = path("prime256v1-key.pem"),
    ?assertEqual(ok, pkix:add_file(File)),
    ?assertEqual(ok, pkix:del_file(File)).

del_non_existent_test() ->
    ?assertEqual(ok, pkix:del_file(path("foo.pem"))).

add_non_existent_test() ->
    ?assertEqual({error, enoent}, pkix:add_file(path("foo.pem"))).

add_del_cert_with_key_test() ->
    ?assertEqual(ok, pkix:add_file(?RSA_SELF_SIGNED)),
    ?assertEqual(ok, pkix:del_file(?RSA_SELF_SIGNED)).

add_empty_file_test() ->
    File = path("empty.pem"),
    ?assertMatch({error, {bad_cert, _, empty}}, pkix:add_file(File)).

add_file_without_pems_test() ->
    File = path("pkix_test.erl"),
    ?assertMatch({error, {bad_cert, _, empty}}, pkix:add_file(File)).

unsupported_pem_1_test() ->
    File = path("dhparam.pem"),
    ?assertMatch({error, {bad_cert, _, empty}}, pkix:add_file(File)).

unsupported_pem_2_test() ->
    File = path("unsupported.pem"),
    ?assertMatch({error, {bad_cert, _, empty}}, pkix:add_file(File)).

ignore_text_between_pems_test() ->
    File = path("text-between.pem"),
    ?assertEqual(ok, pkix:add_file(File)),
    ?assertEqual(ok, pkix:del_file(File)).

unexpected_eof_test() ->
    File = path("unexpected-eof.pem"),
    ?assertMatch({error, {bad_cert, _, unexpected_eof}}, pkix:add_file(File)).

nested_pem_test() ->
    File = path("nested.pem"),
    ?assertMatch({error, {bad_cert, _, nested_pem}}, pkix:add_file(File)).

bad_pem_test() ->
    File = path("bad-pem.pem"),
    ?assertMatch({error, {bad_cert, _, bad_pem}}, pkix:add_file(File)).

bad_der_test() ->
    File = path("bad-der.pem"),
    ?assertMatch({error, {bad_cert, _, bad_der}}, pkix:add_file(File)).

encrypted_key_test() ->
    File = path("encrypted-rsa-key.pem"),
    ?assertMatch({error, {bad_cert, _, encrypted}}, pkix:add_file(File)).

commit_self_signed_no_validate_test() ->
    ?assertEqual(ok, pkix:add_file(?DSA_SELF_SIGNED)),
    ?assertEqual(ok, pkix:add_file(?RSA_SELF_SIGNED)),
    ?assertEqual(ok, pkix:add_file(?EC_SELF_SIGNED)),
    ?assertEqual({ok, [], [], undefined},
		 pkix:commit(test_dir(), [{validate, false}])),
    {EC, RSA, DSA} = pkix:get_certfile(<<"localhost">>),
    ?assertEqual(true, filelib:is_regular(EC)),
    ?assertEqual(true, filelib:is_regular(RSA)),
    ?assertEqual(true, filelib:is_regular(DSA)),
    ?assertEqual(ok, pkix:del_file(?DSA_SELF_SIGNED)),
    ?assertEqual(ok, pkix:del_file(?RSA_SELF_SIGNED)),
    ?assertEqual(ok, pkix:del_file(?EC_SELF_SIGNED)),
    commit_empty().

commit_self_signed_soft_validate_test() ->
    ?assertEqual(ok, pkix:add_file(?DSA_SELF_SIGNED)),
    ?assertEqual(ok, pkix:add_file(?RSA_SELF_SIGNED)),
    ?assertEqual(ok, pkix:add_file(?EC_SELF_SIGNED)),
    ?assertMatch({ok, [], [{_, {invalid_cert, _, selfsigned_peer}},
			   {_, {invalid_cert, _, selfsigned_peer}},
			   {_, {invalid_cert, _, selfsigned_peer}}],
		  undefined},
		 pkix:commit(test_dir(), [])),
    {EC, RSA, DSA} = pkix:get_certfile(<<"localhost">>),
    ?assertEqual(true, filelib:is_regular(EC)),
    ?assertEqual(true, filelib:is_regular(RSA)),
    ?assertEqual(true, filelib:is_regular(DSA)),
    ?assertEqual(ok, pkix:del_file(?DSA_SELF_SIGNED)),
    ?assertEqual(ok, pkix:del_file(?RSA_SELF_SIGNED)),
    ?assertEqual(ok, pkix:del_file(?EC_SELF_SIGNED)),
    commit_empty().

commit_self_signed_hard_validate_test() ->
    ?assertEqual(ok, pkix:add_file(?DSA_SELF_SIGNED)),
    ?assertEqual(ok, pkix:add_file(?RSA_SELF_SIGNED)),
    ?assertEqual(ok, pkix:add_file(?EC_SELF_SIGNED)),
    ?assertMatch({ok, [{_, {invalid_cert, _, selfsigned_peer}},
		       {_, {invalid_cert, _, selfsigned_peer}},
		       {_, {invalid_cert, _, selfsigned_peer}}],
		  [], undefined},
		 pkix:commit(test_dir(), [{validate, hard}])),
    ?assertEqual(error, pkix:get_certfile()).

missing_priv_key_test() ->
    Files = [path("rsa-cert.pem"),
	     path("secp384r1-cert.pem"),
	     path("prime256v1-cert.pem"),
	     path("dsa-cert.pem")],
    lists:foreach(
      fun(F) -> ?assertEqual(ok, pkix:add_file(F)) end,
      Files),
    ?assertMatch({ok, [{_, {bad_cert, _, missing_priv_key}},
		       {_, {bad_cert, _, missing_priv_key}},
		       {_, {bad_cert, _, missing_priv_key}},
		       {_, {bad_cert, _, missing_priv_key}}],
		  [], undefined},
		 pkix:commit(test_dir())),
    ?assertEqual(error, pkix:get_certfile()).

unused_priv_key_test() ->
    File = path("rsa-key.pem"),
    ?assertEqual(ok, pkix:add_file(File)),
    ?assertMatch({ok, [],
		  [{_, {invalid_cert, _, unused_priv_key}}],
		  undefined},
		 pkix:commit(test_dir())),
    ?assertEqual(error, pkix:get_certfile()).

commit_valid_test() ->
    File = path("valid-cert.pem"),
    ?assertEqual(ok, pkix:add_file(File)),
    ?assertEqual({ok, [], [], undefined},
		 pkix:commit(test_dir(), [{cafile, path("ca.pem")}])),
    {undefined, RSA, undefined} = pkix:get_certfile(<<"localhost">>),
    {undefined, RSA, undefined} = pkix:get_certfile(<<"foo.localhost">>),
    ?assertEqual(true, filelib:is_regular(RSA)),
    ?assertEqual(ok, pkix:del_file(File)),
    commit_empty().

commit_valid_chain_test() ->
    File = path("valid-cert.pem"),
    CAFile = path("ca.pem"),
    ?assertEqual(ok, pkix:add_file(File)),
    ?assertEqual(ok, pkix:add_file(CAFile)),
    ?assertEqual({ok, [], [], undefined},
		 pkix:commit(test_dir(), [{cafile, CAFile}])),
    {undefined, RSA, undefined} = pkix:get_certfile(<<"localhost">>),
    {undefined, RSA, undefined} = pkix:get_certfile(<<"foo.localhost">>),
    ?assertEqual(true, filelib:is_regular(RSA)),
    ?assertEqual(ok, pkix:del_file(File)),
    ?assertEqual(ok, pkix:del_file(CAFile)),
    commit_empty().

non_existent_cafile_test() ->
    ?assertEqual(ok, pkix:add_file(?DSA_SELF_SIGNED)),
    ?assertEqual(ok, pkix:add_file(?RSA_SELF_SIGNED)),
    ?assertEqual(ok, pkix:add_file(?EC_SELF_SIGNED)),
    CAFile = path("foo"),
    ?assertMatch({ok, _, _, {CAFile, enoent}},
		 pkix:commit(test_dir(), [{cafile, CAFile}])),
    {EC, RSA, DSA} = pkix:get_certfile(<<"localhost">>),
    ?assertEqual(true, filelib:is_regular(EC)),
    ?assertEqual(true, filelib:is_regular(RSA)),
    ?assertEqual(true, filelib:is_regular(DSA)),
    ?assertEqual(ok, pkix:del_file(?DSA_SELF_SIGNED)),
    ?assertEqual(ok, pkix:del_file(?RSA_SELF_SIGNED)),
    ?assertEqual(ok, pkix:del_file(?EC_SELF_SIGNED)),
    commit_empty().

commit_valid_with_bad_cafile_test() ->
    File = path("valid-cert.pem"),
    CAFile = path("bad-pem.pem"),
    ?assertEqual(ok, pkix:add_file(File)),
    ?assertMatch({ok, [{_, {invalid_cert, _, unknown_ca}}],
		  [], {CAFile, {bad_cert, _, bad_pem}}},
		 pkix:commit(test_dir(), [{cafile, CAFile}, {validate, hard}])),
    ?assertEqual(error, pkix:get_certfile()).

commit_bad_dir_test() ->
    Dir = filename:join([test_dir(), "empty.pem", "foo"]),
    ?assertMatch({error, _, _}, pkix:commit(Dir)).

no_domain_test() ->
    File = path("no-domain.pem"),
    ?assertEqual(ok, pkix:add_file(File)),
    ?assertEqual({ok, [], [], undefined},
		 pkix:commit(test_dir(), [{validate, false}])),
    {undefined, RSA, undefined} = pkix:get_certfile(<<>>),
    ?assertEqual(true, filelib:is_regular(RSA)),
    ?assertEqual(ok, pkix:del_file(File)),
    commit_empty().

get_certfile_test() ->
    File = path("no-domain.pem"),
    ?assertEqual(error, pkix:get_certfile()),
    ?assertEqual(ok, pkix:add_file(File)),
    ?assertEqual({ok, [], [], undefined},
		 pkix:commit(test_dir(), [{validate, false}])),
    {undefined, RSA, undefined} = pkix:get_certfile(),
    ?assertEqual(true, filelib:is_regular(RSA)),
    ?assertEqual(ok, pkix:del_file(File)),
    commit_empty(),
    ?assertEqual(error, pkix:get_certfile()).

sort_by_validity_test() ->
    Invalid = path("rsa-self-signed.pem"),
    Valid = path("valid-cert.pem"),
    CAFile = path("ca.pem"),
    ?assertEqual(ok, pkix:add_file(Valid)),
    ?assertEqual(ok, pkix:add_file(Invalid)),
    ?assertMatch({ok, _, _, undefined},
		 pkix:commit(test_dir(), [{cafile, CAFile}])),
    {undefined, File, undefined} = pkix:get_certfile(<<"localhost">>),
    pem_files_are_equal(Valid, File),
    ?assertEqual(ok, pkix:del_file(Valid)),
    ?assertEqual(ok, pkix:del_file(Invalid)),
    commit_empty().

sort_by_expiration_date_test() ->
    Old = path("old.pem"),
    New = path("new.pem"),
    ?assertEqual(ok, pkix:add_file(Old)),
    ?assertEqual(ok, pkix:add_file(New)),
    ?assertMatch({ok, _, _, undefined}, pkix:commit(test_dir())),
    {undefined, File, undefined} = pkix:get_certfile(<<>>),
    pem_files_are_equal(New, File),
    ?assertEqual(ok, pkix:del_file(Old)),
    ?assertEqual(ok, pkix:del_file(New)),
    commit_empty().

unexpected_call_test() ->
    ?assertExit({timeout, _}, gen_server:call(pkix, eunit_call, 10)).

unexpected_cast_test() ->
    ?assertEqual(ok, gen_server:cast(pkix, eunit_cast)).

unexpected_info_test() ->
    ?assertEqual(eunit_info, erlang:send(pkix, eunit_info)).

format_error_test() ->
    Bad = [missing_priv_key, bad_der, bad_pem, empty,
	   encrypted, unknown_key_algo, unknown_key_type,
	   unexpected_eof, nested_pem],
    Invalid = [cert_expired, invalid_issuer, invalid_signature,
	       name_not_permitted, missing_basic_constraint,
	       invalid_key_usage, selfsigned_peer, unknown_ca,
	       unused_priv_key],
    lists:foreach(
      fun(BadErr) ->
	      ?assertNotMatch("unexpected " ++ _,
			      pkix:format_error({bad_cert, 1, BadErr}))
      end, Bad),
    lists:foreach(
      fun(InvalidErr) ->
	      Unexpected = "at line 1: " ++ atom_to_list(InvalidErr),
	      ?assertNotEqual(Unexpected,
			      pkix:format_error({invalid_cert, 1, InvalidErr}))
      end, Invalid),
    ?assertEqual("at line 1: unexpected",
		 pkix:format_error({invalid_cert, 1, unexpected})),
    ?assertEqual("unexpected", pkix:format_error(unexpected)),
    ?assertEqual("unexpected error: 123", pkix:format_error(123)).

removed_before_commit_test() ->
    {ok, CWD} = file:get_cwd(),
    Src = path("valid-cert.pem"),
    Dst = filename:join(CWD, "valid-cert.pem"),
    ?assertMatch({ok, _}, file:copy(Src, Dst)),
    ?assertEqual(ok, pkix:add_file(Dst)),
    ?assertEqual(ok, file:delete(Dst)),
    ?assertMatch({ok, [{_, enoent}], [], undefined},
		 pkix:commit(test_dir())).

stop_test() ->
    ?assertEqual(ok, pkix:stop()).

%%%===================================================================
%%% Internal functions
%%%===================================================================
test_dir() ->
    {ok, Cwd} = file:get_cwd(),
    filename:join(filename:dirname(Cwd), "test").

path(File) ->
    unicode:characters_to_binary(filename:join(test_dir(), File)).

commit_empty() ->
    ?assertEqual({ok, [], [], undefined}, pkix:commit(test_dir())),
    ?assertEqual([], pkix:get_certfiles()).

pem_files_are_equal(File1, File2) ->
    {ok, Data1} = file:read_file(File1),
    {ok, Data2} = file:read_file(File2),
    PEM1 = lists:sort(public_key:pem_decode(Data1)),
    PEM2 = lists:sort(public_key:pem_decode(Data2)),
    ?assertEqual(hd(PEM1), hd(PEM2)).
