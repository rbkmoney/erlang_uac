-module(uac_conf).

%%

-export([get_child_spec/0]).
-export([init/1]).

%% API

-export([configure/1]).
-export([get_issuer_service/0]).
-export([get_accepted_services/0]).
-export([get_operation_access/2]).
-export([get_resource_hierarchy/0]).

-type operation_id() :: atom().
-type operation_access_scopes() :: [{uac_acl:scope(), uac_acl:permission()}].

-type options() :: #{
    issuer_service := binary(),
    accepted_services := list(binary()),
    resource_hierarchy := #{atom() => map()},
    operations := #{atom() => operation_access_scopes()}
}.
-export_type([options/0]).

%%

-spec get_child_spec() ->
    [supervisor:child_spec()].

get_child_spec() ->
    [#{
        id => ?MODULE,
        start => {supervisor, start_link, [?MODULE, []]},
        type => supervisor
    }].

-spec init([]) ->
    {ok, {supervisor:sup_flags(), [supervisor:child_spec()]}}.

init([]) ->
    ok = create_table(),
    {ok, {#{}, []}}.

%%
%% API
%%

-spec get_issuer_service() ->
    binary().
get_issuer_service() ->
    lookup_value(issuer_service).

-spec get_accepted_services() ->
    list(binary()).
get_accepted_services() ->
    lookup_value(accepted_services).

-spec get_operation_access(operation_id(), _) ->
    operation_access_scopes().
get_operation_access(OpName, _Req) ->
    Operations = lookup_value(operations),
    maps:get(OpName, Operations).

-spec get_resource_hierarchy() ->
    #{atom() => map()}.
get_resource_hierarchy() ->
    lookup_value(resource_hierarchy).

%%

-spec configure(options()) ->
    ok.
configure(Config) ->
    ok = insert_values(Config).

%%

-define(TABLE, ?MODULE).

create_table() ->
    _ = ets:new(?TABLE, [set, public, named_table, {read_concurrency, true}]),
    ok.

insert_values(Values) ->
    true = ets:insert(?TABLE, maps:to_list(Values)),
    ok.

lookup_value(Key) ->
    lookup_value(Key, undefined).

lookup_value(Key, Default) ->
    case ets:lookup(?TABLE, Key) of
        [{Key, Value}] ->
            Value;
        [] ->
            Default
    end.
