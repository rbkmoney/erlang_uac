-module(uac_util).

-export([issue_access_token/4]).
-export([issue_invoice_access_token/2]).
-export([issue_invoice_access_token/3]).
-export([issue_invoice_template_access_token/2]).
-export([issue_invoice_template_access_token/3]).
-export([issue_customer_access_token/2]).
-export([issue_customer_access_token/3]).

-export([get_subject_id/1]).
-export([get_claims/1]).
-export([get_claim/2]).
-export([get_claim/3]).

%% TODO
%% Hardcode for now, should pass it here probably as an argument
-define(DEFAULT_INVOICE_ACCESS_TOKEN_LIFETIME, 259200).
-define(DEFAULT_CUSTOMER_ACCESS_TOKEN_LIFETIME, 259200).

-spec issue_invoice_access_token(PartyID :: binary(), InvoiceID :: binary()) ->
    {ok, uac_authorizer_jwt:token()} | {error, _}.

issue_invoice_access_token(PartyID, InvoiceID) ->
    issue_invoice_access_token(PartyID, InvoiceID, #{}).

-spec issue_invoice_access_token(PartyID :: binary(), InvoiceID :: binary(), uac_auth:claims()) ->
    {ok, uac_authorizer_jwt:token()} | {error, _}.

issue_invoice_access_token(PartyID, InvoiceID, Claims) ->
    ACL = [
        {[{invoices, InvoiceID}]           , read},
        {[{invoices, InvoiceID}, payments] , read},
        {[{invoices, InvoiceID}, payments] , write},
        {[payment_resources]               , write}
    ],
    issue_access_token(PartyID, Claims, ACL, {lifetime, ?DEFAULT_INVOICE_ACCESS_TOKEN_LIFETIME}).

-spec issue_invoice_template_access_token(PartyID :: binary(), InvoiceTplID :: binary()) ->
    {ok, uac_authorizer_jwt:token()} | {error, _}.

issue_invoice_template_access_token(PartyID, InvoiceID) ->
    issue_invoice_template_access_token(PartyID, InvoiceID, #{}).


-spec issue_invoice_template_access_token(PartyID :: binary(), InvoiceTplID :: binary(), uac_auth:claims()) ->
    {ok, uac_authorizer_jwt:token()} | {error, _}.

issue_invoice_template_access_token(PartyID, InvoiceTplID, Claims) ->
    ACL = [
        {[party, {invoice_templates, InvoiceTplID}] , read},
        {[party, {invoice_templates, InvoiceTplID}, invoice_template_invoices] , write}
    ],
    issue_access_token(PartyID, Claims, ACL, unlimited).

-spec issue_customer_access_token(PartyID :: binary(), CustomerID :: binary()) ->
    {ok, uac_authorizer_jwt:token()} | {error, _}.

issue_customer_access_token(PartyID, CustomerID) ->
    issue_customer_access_token(PartyID, CustomerID, #{}).

-spec issue_customer_access_token(PartyID :: binary(), CustomerID :: binary(), uac_auth:claims()) ->
    {ok, uac_authorizer_jwt:token()} | {error, _}.

issue_customer_access_token(PartyID, CustomerID, Claims) ->
    ACL = [
        {[{customers, CustomerID}], read},
        {[{customers, CustomerID}, bindings], read},
        {[{customers, CustomerID}, bindings], write},
        {[payment_resources], write}
    ],
    issue_access_token(PartyID, Claims, ACL, {lifetime, ?DEFAULT_CUSTOMER_ACCESS_TOKEN_LIFETIME}).

-type acl() :: [{uac_acl:scope(), uac_acl:permission()}].

-spec issue_access_token(PartyID :: binary(), uac_auth:claims(), acl(), uac_authorizer_jwt:expiration()) ->
    {ok, uac_authorizer_jwt:token()} | {error, _}.

issue_access_token(PartyID, Claims, ACL, Expiration) ->
    uac_authorizer_jwt:issue({{PartyID, uac_acl:from_list(ACL)}, Claims}, Expiration).

-spec get_subject_id(uac_auth:context()) -> binary().

get_subject_id({{SubjectID, _ACL}, _}) ->
    SubjectID.

-spec get_claims(uac_auth:context()) -> uac_autth:claims().

get_claims({_Subject, Claims}) ->
    Claims.

-spec get_claim(binary(), uac_auth:context()) -> term().

get_claim(ClaimName, {_Subject, Claims}) ->
    maps:get(ClaimName, Claims).

-spec get_claim(binary(), uac_auth:context(), term()) -> term().

get_claim(ClaimName, {_Subject, Claims}, Default) ->
    maps:get(ClaimName, Claims, Default).
