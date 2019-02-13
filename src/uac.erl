-module(uac).

%% App

-behaviour(application).
-export([start/2, stop/1]).

%% Supervisor

-behaviour(supervisor).
-export([init/1]).

%%API

-export([configure/1]).
-export([authorize_api_key/3]).
-export([authorize_operation/3]).

-type context() :: uac_authorizer_jwt:t().
-type claims()  :: uac_authorizer_jwt:claims().

-type configuration() :: #{
    jwt := uac_authorizer_jwt:options(),
    access := uac_conf:options()
}.

-type verification_opts() :: #{
    %% If we want to force the token expiration check
    %% We probably only want this when we have the means to notify clients about expiring tokens
    force_expiration => boolean(),

    %% Current time
    current_time := genlib_time:ts()
}.

-type operation_id() :: atom().
-type api_key()      :: binary().

-export_type([context/0]).
-export_type([claims/0]).
-export_type([verification_opts/0]).

%%
% API
%%

-spec configure(configuration()) ->
    ok.
configure(Config) ->
    AuthorizerConfig = maps:get(jwt, Config),
    AccessConfig = maps:get(access, Config),
    ok = uac_authorizer_jwt:configure(AuthorizerConfig),
    ok = uac_conf:configure(AccessConfig).

-spec authorize_api_key(
    OperationID :: operation_id(),
    ApiKey      :: api_key(),
    VerificationOpts :: verification_opts()
) -> {true, Context :: context()} | false.

authorize_api_key(OperationID, ApiKey, VerificationOpts) ->
    case parse_api_key(ApiKey) of
        {ok, {Type, Credentials}} ->
            case authorize_api_key(OperationID, Type, Credentials, VerificationOpts) of
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
    Credentials :: binary(),
    VerificationOpts :: verification_opts()
) ->
    {ok, Context :: context()} | {error, Reason :: atom()}.

authorize_api_key(_OperationID, bearer, Token, VerificationOpts) ->
    % NOTE
    % We are knowingly delegating actual request authorization to the logic handler
    % so we could gather more data to perform fine-grained access control.
    uac_authorizer_jwt:verify(Token, VerificationOpts).

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
    Access = uac_conf:get_operation_access(OperationID, Req),
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
    AuthorizerSpec = uac_authorizer_jwt:get_child_spec(),
    AccessSpec = uac_conf:get_child_spec(),
    SupFlags = #{},
    Children = AuthorizerSpec ++ AccessSpec,
    {ok, {SupFlags, Children}}.
