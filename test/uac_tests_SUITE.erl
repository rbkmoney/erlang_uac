-module(uac_tests_SUITE).

-include_lib("stdlib/include/assert.hrl").
-include_lib("common_test/include/ct.hrl").
-include_lib("jose/include/jose_jwk.hrl").

-export([all/0]).
-export([init_per_suite/1]).
-export([end_per_suite/1]).

-export([
    successful_auth_test/1,
    multiple_domain_successful_auth_test/1,
    invalid_permissions_test/1,
    bad_token_test/1,
    no_token_test/1,
    force_expiration_test/1,
    force_expiration_fail_test/1,
    bad_signee_test/1,
    different_issuers_test/1,
    unknown_resources_ok_test/1,
    unknown_resources_fail_encode_test/1,
    no_resource_access_token_test/1,
    cant_authorize_without_resouce_access_test/1
]).

-type test_case_name()  :: atom().
-type config()          :: [{atom(), any()}].

-define(EXPIRE_AS_OF_NOW, #{
    claim_validators => #{
        <<"exp">> => uac_authorizer_jwt:check_expiration_as_of(genlib_time:unow())
    }
}).

-define(TEST_SERVICE_ACL(Access),
    [{[test_resource], Access}]
).

-define(TEST_DOMAIN_NAME, <<"test">>).

-spec all() ->
    [test_case_name()].
all() ->
    [
        successful_auth_test,
        multiple_domain_successful_auth_test,
        invalid_permissions_test,
        bad_token_test,
        no_token_test,
        force_expiration_test,
        force_expiration_fail_test,
        bad_signee_test,
        unknown_resources_ok_test,
        unknown_resources_fail_encode_test,
        different_issuers_test,
        no_resource_access_token_test,
        cant_authorize_without_resouce_access_test
    ].

-spec init_per_suite(config()) ->
    config().
init_per_suite(Config) ->
    Apps = [
        genlib_app:start_application(snowflake),
        genlib_app:start_application(uac)
    ],
    uac:configure(#{
        jwt => #{
            keyset => #{
                test => {pem_file, get_keysource("keys/local/private.pem", Config)}
            }
        },
        access => #{
            domain_name => ?TEST_DOMAIN_NAME,
            resource_hierarchy => #{
                test_resource => #{}
            }
        }
    }),
    [{apps, Apps}] ++ Config.

-spec end_per_suite(config()) ->
    _.
end_per_suite(Config) ->
    Config.

%%

-spec successful_auth_test(config()) ->
    _.
successful_auth_test(_) ->
    {ok, Token} = issue_token(?TEST_SERVICE_ACL(write), unlimited),
    {ok, AccessContext} = uac:authorize_api_key(<<"Bearer ", Token/binary>>, #{}),
    ok = uac:authorize_operation(?TEST_SERVICE_ACL(write), AccessContext).


-spec multiple_domain_successful_auth_test(config()) ->
    _.
multiple_domain_successful_auth_test(_) ->
    ACL1 = ?TEST_SERVICE_ACL(write),
    ACL2 = ?TEST_SERVICE_ACL(read),
    Domain1  = <<"api-1">>,
    Domain2  = <<"api-2">>,
    {ok, Token} = issue_token(#{
        Domain1 => uac_acl:from_list(ACL1),
        Domain2 => uac_acl:from_list(ACL2)
    }, unlimited),
    ok = uac_conf:configure(#{
        domain_name => Domain1
    }),
    {ok, AccessContext1} = uac:authorize_api_key(<<"Bearer ", Token/binary>>, #{}),
    ok = uac:authorize_operation(ACL1, AccessContext1),


    ok = uac_conf:configure(#{
        domain_name => Domain2
    }),
    {ok, AccessContext2} = uac:authorize_api_key(<<"Bearer ", Token/binary>>, #{}),
    ok = uac:authorize_operation(ACL2, AccessContext2).


-spec invalid_permissions_test(config()) ->
    _.
invalid_permissions_test(_) ->
    {ok, Token} = issue_token(
        [{[test_resource], read}, {{unknown, <<"other_test">>}, write}],
        unlimited
    ),
    {ok, AccessContext} = uac:authorize_api_key(<<"Bearer ", Token/binary>>, #{}),
    {error, _} = uac:authorize_operation(?TEST_SERVICE_ACL(write), AccessContext).

-spec bad_token_test(config()) ->
    _.
bad_token_test(Config) ->
    {ok, Token} = issue_dummy_token(?TEST_SERVICE_ACL(write), Config),
    {error, _} = uac:authorize_api_key(<<"Bearer ", Token/binary>>, #{}).

-spec no_token_test(config()) ->
    _.
no_token_test(_) ->
    Token = <<"">>,
    {error, _} = uac:authorize_api_key(<<"Bearer ", Token/binary>>, #{}).

-spec force_expiration_test(config()) ->
    _.
force_expiration_test(_) ->
    {ok, Token} = issue_token(?TEST_SERVICE_ACL(write), {deadline, 1}),
    {ok, AccessContext} = uac:authorize_api_key(<<"Bearer ", Token/binary>>, #{}),
    ok = uac:authorize_operation(?TEST_SERVICE_ACL(write), AccessContext).

-spec force_expiration_fail_test(config()) ->
    _.
force_expiration_fail_test(_) ->
    {ok, Token} = issue_token(?TEST_SERVICE_ACL(write), {deadline, 1}),
    {error, _} = uac:authorize_api_key(<<"Bearer ", Token/binary>>, ?EXPIRE_AS_OF_NOW).

-spec bad_signee_test(config()) ->
    _.
bad_signee_test(_) ->
    ACL = ?TEST_SERVICE_ACL(write),
    {error, nonexistent_key} =
        uac_authorizer_jwt:issue(unique_id(), unlimited, {<<"TEST">>, uac_acl:from_list(ACL)}, #{}, random).

%%

-spec different_issuers_test(config()) ->
    _.
different_issuers_test(_) ->
    {ok, Token} = issue_token(?TEST_SERVICE_ACL(write), unlimited),
    ok = uac_conf:configure(#{
        domain_name => <<"SOME_OTHER_SERVICE">>
    }),
    {ok, {_, {_, []}, _}} = uac:authorize_api_key(<<"Bearer ", Token/binary>>, #{}),
    ok = uac_conf:configure(#{
        domain_name => ?TEST_DOMAIN_NAME
    }).

-spec unknown_resources_ok_test(config()) ->
    _.
unknown_resources_ok_test(_) ->
    ok = uac_conf:configure(#{
        resource_hierarchy => #{
            different_resource           => #{},
            test_resource                => #{},
            even_more_different_resource => #{}
        }
    }),
    ACL = [{[different_resource], read}, {[test_resource], write}, {[even_more_different_resource], read}],
    {ok, Token} = issue_token(ACL, unlimited),
    ok = uac_conf:configure(#{
        resource_hierarchy => #{
            test_resource => #{}
        }
    }),
    {ok, AccessContext} = uac:authorize_api_key(<<"Bearer ", Token/binary>>, #{}),
    ok = uac:authorize_operation(?TEST_SERVICE_ACL(write), AccessContext).

-spec no_resource_access_token_test(config()) ->
    _.
no_resource_access_token_test(_) ->
    {ok, Token} = issue_token(#{}, unlimited),
    {ok, {_, _, Claims}} = uac_authorizer_jwt:verify(Token, #{}),
    undefined = maps:get(<<"resource_access">>, Claims, undefined),
    {ok, _} = uac_authorizer_jwt:verify(Token, #{}).

-spec cant_authorize_without_resouce_access_test(config()) ->
    _.
cant_authorize_without_resouce_access_test(_) ->
    {ok, Token} = issue_token(#{}, unlimited),
    {error, {invalid_token, {missing, resource_access}}} = uac_authorizer_jwt:verify(Token, #{claim_validators => #{
        <<"resource_access">> => uac_authorizer_jwt:check_presence(resource_access)
    }}).
-spec unknown_resources_fail_encode_test(config()) ->
    _.
unknown_resources_fail_encode_test(_) ->
    ACL = [{[different_resource], read}, {[test_resource], write}, {[even_more_different_resource], read}],
    ?assertError({badarg, {resource, _}}, issue_token(ACL, unlimited)).
%%

issue_token(DomainRoles, LifeTime) when is_map(DomainRoles) ->
    PartyID = <<"TEST">>,
    Claims = #{<<"TEST">> => <<"TEST">>},
    uac_authorizer_jwt:issue(unique_id(), LifeTime, PartyID, DomainRoles, Claims, test);

issue_token(ACL, LifeTime) ->
    PartyID = <<"TEST">>,
    Claims = #{<<"TEST">> => <<"TEST">>},
    uac_authorizer_jwt:issue(unique_id(), LifeTime, {PartyID, uac_acl:from_list(ACL)}, Claims, test).

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
