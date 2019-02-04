-module(uac).

%% App

-behaviour(application).
-export([start/2, stop/1]).

%% Supervisor

-behaviour(supervisor).
-export([init/1]).

%%API

-export([authorize_api_key/2]).
-export([authorize_operation/3]).

-export([get_resource_hierarchy/0]).
-export([get_issuer_namespace/0]).
-export([get_accepted_namespaces/0]).

-type context() :: uac_authorizer_jwt:t().
-type claims()  :: uac_authorizer_jwt:claims().

-type operation_id() :: atom().
-type api_key()      :: binary().

-export_type([context/0]).
-export_type([claims/0]).


%%
% API
%%

-spec authorize_api_key(
    OperationID :: operation_id(),
    ApiKey      :: api_key()
) -> {true, Context :: context()} | false.

authorize_api_key(OperationID, ApiKey) ->
    case parse_api_key(ApiKey) of
        {ok, {Type, Credentials}} ->
            case authorize_api_key(OperationID, Type, Credentials) of
                {ok, Context} ->
                    {true, Context};
                {error, Error} ->
                    _ = log_auth_error(OperationID, Error),
                    false
            end;
        {error, Error} ->
            _ = log_auth_error(OperationID, Error),
            false
    end.

log_auth_error(OperationID, Error) ->
    lager:info("API Key authorization failed for ~p due to ~p", [OperationID, Error]).

-spec parse_api_key(ApiKey :: api_key()) ->
    {ok, {bearer, Credentials :: binary()}} | {error, Reason :: atom()}.

parse_api_key(ApiKey) ->
    case ApiKey of
        <<"Bearer ", Credentials/binary>> ->
            {ok, {bearer, Credentials}};
        _ ->
            {error, unsupported_auth_scheme}
    end.

-spec authorize_api_key(
    OperationID :: operation_id(),
    Type :: atom(),
    Credentials :: binary()
) ->
    {ok, Context :: context()} | {error, Reason :: atom()}.

authorize_api_key(_OperationID, bearer, Token) ->
    % NOTE
    % We are knowingly delegating actual request authorization to the logic handler
    % so we could gather more data to perform fine-grained access control.
    uac_authorizer_jwt:verify(Token).

%%

% TODO
% We need shared type here, exported somewhere in swagger app
-type request_data() :: #{atom() | binary() => term()}.

-spec authorize_operation(
    OperationID :: operation_id(),
    Req :: request_data(),
    Auth :: uac_authorizer_jwt:t()
) ->
    ok | {error, unauthorized}.

authorize_operation(OperationID, Req, {{_SubjectID, ACL}, _}) ->
    Access = get_operation_access(OperationID, Req),
    case lists:all(
        fun ({Scope, Permission}) ->
            lists:member(Permission, uac_acl:match(Scope, ACL))
        end,
        Access
    ) of
        true ->
            ok;
        false ->
            {error, unauthorized}
    end.

%%

-spec get_operation_access(operation_id(), request_data()) ->
    [{uac_acl:scope(), uac_acl:permission()}].

get_operation_access(Op, _) ->
    Operations = genlib_app:env(?MODULE, operations, #{}),
    maps:get(Op, Operations).

-spec get_resource_hierarchy() -> #{atom() => map()}.

get_resource_hierarchy() ->
    genlib_app:env(?MODULE, resource_hierarchy, #{}).

-spec get_issuer_namespace() -> binary().
get_issuer_namespace() ->
    genlib_app:env(?MODULE, issuer_service).

-spec get_accepted_namespaces() -> list(binary()).
get_accepted_namespaces() ->
    genlib_app:env(?MODULE, accepted_services, []).


%%
% App
%%

-spec start(any(), any()) ->
    {ok, pid()} | {error, Reason :: term()}.
start(_StartType, _StartArgs) ->
    supervisor:start_link({local, ?MODULE}, ?MODULE, []).

-spec stop(any()) ->
    ok.
stop(_State) ->
    ok.

%%
% Supervisor
%%

-spec init([]) ->
    {ok, {supervisor:sup_flags(), [supervisor:child_spec()]}}.
init([]) ->
    AuthorizerSpecs = get_authorizer_child_specs(),
    SupFlags = #{},
    Children = AuthorizerSpecs,
    {ok, {SupFlags, Children}}.

%%

get_authorizer_child_specs() ->
    Authorizers = genlib_app:env(?MODULE, authorizers, #{}),
    [
        get_authorizer_child_spec(jwt, maps:get(jwt, Authorizers))
    ].

get_authorizer_child_spec(jwt, Options) ->
    uac_authorizer_jwt:get_child_spec(Options).
