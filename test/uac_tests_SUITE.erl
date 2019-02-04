-module(uac_tests_SUITE).

-include_lib("common_test/include/ct.hrl").
-include_lib("jose/include/jose_jwk.hrl").

-export([all/0]).
-export([groups/0]).
-export([init_per_suite/1]).
-export([end_per_suite/1]).
-export([init_per_group/2]).
-export([end_per_group/2]).
-export([init_per_testcase/2]).
-export([end_per_testcase/2]).

-export([
    successful_auth_test/1,
    invalid_permissions_test/1,
    bad_token_test/1,
    no_token_test/1,

    different_issuers_test/1,
    incompatible_issuers_test/1
]).

-type test_case_name()  :: atom().
-type config()          :: [{atom(), any()}].
-type group_name()      :: atom().

-spec all() ->
    [test_case_name()].
all() ->
    [
        {group, general_tests},
        {group, different_issuers},
        {group, incompatible_issuers}
    ].

-spec groups() ->
    [{group_name(), list(), [test_case_name()]}].
groups() ->
    [
        {general_tests, [],
            [
                successful_auth_test,
                invalid_permissions_test,
                bad_token_test,
                no_token_test
            ]
        },
        {different_issuers, [],
            [
                different_issuers_test
            ]
        },
        {incompatible_issuers, [],
            [
                incompatible_issuers_test
            ]
        }
    ].

-spec init_per_suite(config()) ->
    config().
init_per_suite(Config) ->
    Config.

-spec init_per_group(group_name(), config()) ->
    config().
init_per_group(general_tests, Config) ->
    Apps = genlib_app:start_application_with(uac, [
        {issuer_service, <<"test">>},
        {accepted_services, [<<"test">>, <<"test2">>]},
        {authorizers, #{
            jwt => #{
                signee => test,
                keyset => #{
                    test => {pem_file, get_keysource("keys/local/private.pem", Config)}
                }
            }
        }},
        {resource_hierarchy, #{
            test_resource => #{}
        }},
        {operations, #{
            'SomeTestOperation' => [{[test_resource], write}]
        }}
    ]),
    [{apps, Apps}] ++ Config;
init_per_group(different_issuers, Config) ->
    Apps = genlib_app:start_application_with(uac, [
        {issuer_service, <<"test2">>},
        {accepted_services, [<<"test">>, <<"test2">>]},
        {authorizers, #{
            jwt => #{
                signee => test,
                keyset => #{
                    test => {pem_file, get_keysource("keys/local/private.pem", Config)}
                }
            }
        }},
        {resource_hierarchy, #{
            test_resource => #{}
        }},
        {operations, #{
            'SomeTestOperation' => [{[test_resource], write}]
        }}
    ]),
    [{apps, Apps}] ++ Config;
init_per_group(incompatible_issuers, Config) ->
    Apps = genlib_app:start_application_with(uac, [
        {issuer_service, <<"test">>},
        {accepted_services, [<<"SOME">>, <<"OTHER">>, <<"SERVICES">>]},
        {authorizers, #{
            jwt => #{
                signee => test,
                keyset => #{
                    test => {pem_file, get_keysource("keys/local/private.pem", Config)}
                }
            }
        }},
        {resource_hierarchy, #{
            test_resource => #{}
        }},
        {operations, #{
            'SomeTestOperation' => [{[test_resource], write}]
        }}
    ]),
    [{apps, Apps}] ++ Config.

-spec init_per_testcase(test_case_name(), config()) ->
    config().
init_per_testcase(_Name, Config) ->
    Config.

-spec end_per_suite(config()) ->
    _.
end_per_suite(Config) ->
    Config.

-spec end_per_group(group_name(), config()) ->
    _.
end_per_group(_Name, Config) ->
    [application:stop(App) || App <- ?config(apps, Config)].

-spec end_per_testcase(test_case_name(), config()) ->
    _.
end_per_testcase(_Name, Config) ->
    Config.

%%

-spec successful_auth_test(config()) ->
    _.
successful_auth_test(_) ->
    {ok, Token} = issue_token([{[test_resource], write}], unlimited),
    {true, AccessContext} = uac:authorize_api_key('SomeTestOperation', <<"Bearer ", Token/binary>>),
    ok = uac:authorize_operation('SomeTestOperation', <<"">>, AccessContext).

-spec invalid_permissions_test(config()) ->
    _.
invalid_permissions_test(_) ->
    {ok, Token} = issue_token([{[test_resource], read}], unlimited),
    {true, AccessContext} = uac:authorize_api_key('SomeTestOperation', <<"Bearer ", Token/binary>>),
    {error, _} = uac:authorize_operation('SomeTestOperation', <<"">>, AccessContext).

-spec bad_token_test(config()) ->
    _.
bad_token_test(Config) ->
    {ok, Token} = issue_dummy_token([{[test_resource], write}], Config),
    false = uac:authorize_api_key('SomeTestOperation', <<"Bearer ", Token/binary>>).

-spec no_token_test(config()) ->
    _.
no_token_test(_) ->
    Token = <<"">>,
    false = uac:authorize_api_key('SomeTestOperation', <<"Bearer ", Token/binary>>).

%%

-spec different_issuers_test(config()) ->
    _.
different_issuers_test(_) ->
    {ok, Token} = issue_token([{[test_resource], write}], unlimited),
    {true, AccessContext} = uac:authorize_api_key('SomeTestOperation', <<"Bearer ", Token/binary>>),
    ok = uac:authorize_operation('SomeTestOperation', <<"">>, AccessContext).

%%

-spec incompatible_issuers_test(config()) ->
    _.
incompatible_issuers_test(_) ->
    {ok, Token} = issue_token([{[test_resource], write}], unlimited),
    false = uac:authorize_api_key('SomeTestOperation', <<"Bearer ", Token/binary>>).

%%

issue_token(ACL, LifeTime) ->
    PartyID = <<"TEST">>,
    Claims = #{<<"TEST">> => <<"TEST">>},
    uac_authorizer_jwt:issue({{PartyID, uac_acl:from_list(ACL)}, Claims}, LifeTime).

issue_dummy_token(ACL, Config) ->
    Claims = #{
        <<"jti">> => unique_id(),
        <<"sub">> => <<"TEST">>,
        <<"exp">> => 0,
        <<"resource_access">> => #{
            <<"common-api">> => #{
                <<"roles">> => uac_acl:encode(uac_acl:from_list(ACL))
            }
        }
    },
    BadPemFile = get_keysource("keys/local/dummy.pem", Config),
    BadJWK = jose_jwk:from_pem_file(BadPemFile),
    GoodPemFile = get_keysource("keys/local/private.pem", Config),
    GoodJWK = jose_jwk:from_pem_file(GoodPemFile),
    JWKPublic = jose_jwk:to_public(GoodJWK),
    {_Module, PublicKey} = JWKPublic#jose_jwk.kty,
    {_PemEntry, Data, _} = public_key:pem_entry_encode('SubjectPublicKeyInfo', PublicKey),
    KID = base64url:encode(crypto:hash(sha256, Data)),
    JWT = jose_jwt:sign(BadJWK, #{<<"alg">> => <<"RS256">>, <<"kid">> => KID}, Claims),
    {_Modules, Token} = jose_jws:compact(JWT),
    {ok, Token}.

get_keysource(Key, Config) ->
    filename:join(?config(data_dir, Config), Key).

unique_id() ->
    <<ID:64>> = snowflake:new(),
    genlib_format:format_int_base(ID, 62).
