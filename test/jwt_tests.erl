-module(jwt_tests).
-include_lib("eunit/include/eunit.hrl").
-compile([export_all]).

-define(SECRET, <<"secret">>).

jwt_test_() -> {setup,
    fun start/0, fun stop/1,
    [ fun test_encoding/0
    , fun test_encoding_with_exp/0
    , fun test_encoding_with_undefined_algorithm/0
    , fun test_encoding_with_all_algorithms/0
    , fun test_decoding_simple/0
    , fun test_decoding_simple2/0
    , fun test_decoding_header_error/0
    , fun test_decoding_payload_error/0
    , fun test_decoding_signature_error/0
    , fun test_decoding_very_bad_token/0
    ]}.

start() -> ok.
stop(_) -> ok.

%%
%% Tests
%%

test_encoding() ->
    Claims = [{user_id, 42}, {user_name, <<"John Doe">>}],
    {ok, Token} = jwt:encode(<<"HS256">>, Claims, ?SECRET),

    ExpHeader = <<"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9">>,
    ExpPayload = <<"eyJ1c2VyX2lkIjo0MiwidXNlcl9uYW1lIjoiSm9obiBEb2UifQ">>,
    ExpSignature = <<"cDMB--ajYo0DWsX14wTkWmM385X9OAOPgIPSsJzKZ8E">>,

    ?assertEqual(makeToken(ExpHeader, ExpPayload, ExpSignature), Token).

test_encoding_with_exp() ->
    ExpirationSeconds = 86400,
    Result = jwt:encode(<<"HS256">>, [], ExpirationSeconds, ?SECRET),

    ?assertMatch({ok, _Token}, Result).

test_encoding_with_undefined_algorithm() ->
    Error = jwt:encode(<<"HS128">>, [], ?SECRET),

    ?assertEqual({error, algorithm_not_supported}, Error).

test_encoding_with_all_algorithms() ->
    ?assertMatch({ok, _Token}, jwt:encode(<<"HS256">>, [], ?SECRET)),
    ?assertMatch({ok, _Token}, jwt:encode(<<"HS384">>, [], ?SECRET)),
    ?assertMatch({ok, _Token}, jwt:encode(<<"HS512">>, [], ?SECRET)).

test_decoding_simple() ->
    Header = <<"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9">>,
    Payload = <<"eyJ1c2VyX2lkIjo0MiwidXNlcl9uYW1lIjoiSm9obiBTbm93In0">>,
    Signature = <<"RzveVJs7YQbgVVgtmPRx7lOQOs89pCFxjLIEyzgnFaA">>,

    Claims = jwt:decode(makeToken(Header, Payload, Signature), ?SECRET),

    ?assertMatch({ok, #{ <<"user_id">> := 42
                       , <<"user_name">> := <<"John Snow">>
                       }}, Claims).

test_decoding_simple2() ->
    Header = <<"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9">>,
    Payload = <<"eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0">>,
    Signature = <<"Q6CM1qIz2WTgTlhMzpFL8jI8xbu9FFfj5DY_bGVY98Y">>,

    Claims = jwt:decode(makeToken(Header, Payload, Signature), ?SECRET),
    io.
    ?assertMatch({ok, #{ <<"sub">> := <<"1234567890">>
                       , <<"name">> := <<"John Doe">>
                       }}, Claims).

test_decoding_header_error() ->
    Header = <<"...">>,
    Payload = <<"eyJ1c2VyX2lkIjo0MiwidXNlcl9uYW1lIjoiSm9obiBTbm93In0">>,
    Signature = <<"RzveVJs7YQbgVVgtmPRx7lOQOs89pCFxjLIEyzgnFaA">>,

    Claims = jwt:decode(makeToken(Header, Payload, Signature), ?SECRET),

    ?assertMatch({error, invalid_token}, Claims).

test_decoding_payload_error() ->
    Header = <<"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9">>,
    Payload = <<"...">>,
    Signature = <<"RzveVJs7YQbgVVgtmPRx7lOQOs89pCFxjLIEyzgnFaA">>,

    Claims = jwt:decode(makeToken(Header, Payload, Signature), ?SECRET),

    ?assertMatch({error, invalid_token}, Claims).

test_decoding_signature_error() ->
    Header = <<"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9">>,
    Payload = <<"eyJ1c2VyX2lkIjo0MiwidXNlcl9uYW1lIjoiSm9obiBTbm93In0">>,
    Signature = <<"RzveVJs7YQbgVVgtmPRx7lOQOs89pCFxjLIEyzgnFa">>,

    Claims = jwt:decode(makeToken(Header, Payload, Signature), ?SECRET),

    ?assertMatch({error, invalid_signature}, Claims).

test_decoding_very_bad_token() ->
    Claims = jwt:decode(<<"very_bad">>, ?SECRET),

    ?assertMatch({error, invalid_token}, Claims).

%%
%% Helpers
%%

makeToken(Header, Payload, Sign) ->
    <<Header/binary, ".", Payload/binary, ".", Sign/binary>>.
