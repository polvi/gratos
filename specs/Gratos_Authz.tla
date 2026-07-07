--------------------------- MODULE Gratos_Authz ----------------------------
(***************************************************************************)
(* Tenant-ownership control plane in the gratos-authz worker ("root       *)
(* tenant as authz control plane"; permission-graph evaluation is out of   *)
(* scope). The old bootstrap endpoint is gone.                             *)
(*                                                                         *)
(* Ownership is the set of gratos_tenant:<t>#owner@user:<u> tuples in the  *)
(* root space. They are written ONLY by trusted onboarding actions —       *)
(* domain claim in the provisioner / owned-sandbox mint in gratos-multi —  *)
(* via AuthzRPC.grantTenantOwners (idempotent). No HTTP path can create or *)
(* delete them. Anonymous sandbox tenants never receive owners.            *)
(*                                                                         *)
(* A tenant's schema/tuple mutations (Mutate) are allowed for exactly:     *)
(* (a) the tenant's owner acting through the on-behalf routes (gated by a  *)
(* root-space check of the owner tuple), or (b) ANY authenticated user     *)
(* when the tenant is an anonymous sandbox (throwaway pools are open).     *)
(*                                                                         *)
(* Service tokens (src/tokens.ts, serviceTokenAuth in src/routes.ts): the  *)
(* tenant owner mints/revokes per-tenant Bearer tokens through the         *)
(* on-behalf API (owner-gated, so anonymous sandboxes — which never have   *)
(* owners — never get tokens). A token that verifies for the request's own *)
(* tenant authorizes relationship mutations for THAT tenant only           *)
(* (MutateViaToken, recorded under the pseudo-user svc — owner-delegated   *)
(* authority).                                                             *)
(*                                                                         *)
(* AuthzRPC.cleanupTenant (Cleanup) deletes a tenant's authz data, its     *)
(* ownership tuples AND its service tokens on domain/sandbox delete and    *)
(* sandbox sweep; it refuses the root tenant (the root tenant is simply    *)
(* not in Tenants here). The cron reconcile re-grants missing owner tuples *)
(* from the source-of-truth tables — since grants are idempotent and Claim *)
(* may fire repeatedly, reconcile is just Claim firing again.              *)
(*                                                                         *)
(* Checked properties:                                                     *)
(*   TypeOK                                                                *)
(*   OwnersWereClaimed      — every current owner pair came from the       *)
(*                            trusted grant path (no other source of       *)
(*                            ownership exists).                           *)
(*   NoAnonOwners           — anonymous sandbox tenants never have owners. *)
(*   MutatorsWereAuthorized — every gated mutation was performed by a      *)
(*                            principal authorized at the time: owner of   *)
(*                            the tenant, anon-sandbox user, or a live     *)
(*                            service token of that tenant.                *)
(*   TokensImplyOwnerMinted — every token ever minted was minted by a user *)
(*                            who was owner-claimed on that tenant at mint *)
(*                            time.                                        *)
(*   NoAnonTokens           — anonymous sandbox tenants never hold tokens. *)
(*   TokenMutatorsHadMintedTokens — a token mutation only ever happened on *)
(*                            a tenant for which an owner minted a token.  *)
(***************************************************************************)
EXTENDS FiniteSets

CONSTANTS
    Users,
    Tenants,
    AnonSandbox, \* anonymous sandbox tenants (subset of Tenants)
    TokenIds,    \* small pool of service-token identities
    svc          \* pseudo-user recording token-authorized mutations

ASSUME AnonSandbox \subseteq Tenants
ASSUME svc \notin Users

Principals == Users \cup {svc}

VARIABLES
    owners,           \* current gratos_tenant:<t>#owner@user:<u> tuples, per tenant
    tokens,           \* current live service tokens, per tenant
    claimed,          \* history: <<t,u>> pairs ever granted via the trusted path
    everTokenMintedBy,\* history: <<t,u>> such that u minted a token for t
    mutators,         \* history: <<t,p>> such that principal p performed a gated mutation on t
    everAuthorized    \* history: <<t,p>> authorized at some point (owner then, anon sandbox, or live token then)

vars == <<owners, tokens, claimed, everTokenMintedBy, mutators, everAuthorized>>

Init ==
    /\ owners = [t \in Tenants |-> {}]
    /\ tokens = [t \in Tenants |-> {}]
    /\ claimed = {}
    /\ everTokenMintedBy = {}
    /\ mutators = {}
    /\ everAuthorized = {}

\* Trusted onboarding grant (provisioner domain claim / owned-sandbox mint
\* calling AuthzRPC.grantTenantOwners). Idempotent — may fire repeatedly,
\* which also models the cron reconcile re-granting from source of truth.
Claim(t, u) ==
    /\ t \notin AnonSandbox
    /\ owners' = [owners EXCEPT ![t] = @ \cup {u}]
    /\ claimed' = claimed \cup {<<t, u>>}
    /\ UNCHANGED <<tokens, everTokenMintedBy, mutators, everAuthorized>>

\* Gated schema/tuple mutation: tenant owner via on-behalf routes, or any
\* authenticated user when the tenant is an anonymous (open) sandbox.
Mutate(t, u) ==
    /\ u \in owners[t] \/ t \in AnonSandbox
    /\ mutators' = mutators \cup {<<t, u>>}
    /\ everAuthorized' = everAuthorized \cup {<<t, u>>}
    /\ UNCHANGED <<owners, tokens, claimed, everTokenMintedBy>>

\* Owner mints a per-tenant service token through the on-behalf API
\* (POST /v1/authz/tenants/:target/tokens). Owner-gated, so anonymous
\* sandboxes — which never have owners — can never acquire tokens.
MintToken(t, by, k) ==
    /\ by \in owners[t]
    /\ tokens' = [tokens EXCEPT ![t] = @ \cup {k}]
    /\ everTokenMintedBy' = everTokenMintedBy \cup {<<t, by>>}
    /\ UNCHANGED <<owners, claimed, mutators, everAuthorized>>

\* Owner revokes one of the tenant's tokens
\* (DELETE /v1/authz/tenants/:target/tokens/:id).
RevokeToken(t, by, k) ==
    /\ by \in owners[t]
    /\ k \in tokens[t]
    /\ tokens' = [tokens EXCEPT ![t] = @ \ {k}]
    /\ UNCHANGED <<owners, claimed, everTokenMintedBy, mutators, everAuthorized>>

\* Relationship mutation via `Authorization: Bearer agk_...` on the tenant's
\* own host (serviceTokenAuth): a live token of THIS tenant is delegated owner
\* authority, recorded under svc. everAuthorized is extended from the actual
\* token state — not the guard — so a broken guard is caught by
\* MutatorsWereAuthorized rather than silently self-justifying.
MutateViaToken(t) ==
    /\ tokens[t] # {}
    /\ mutators' = mutators \cup {<<t, svc>>}
    /\ everAuthorized' = everAuthorized \cup
           (IF tokens[t] # {} THEN {<<t, svc>>} ELSE {})
    /\ UNCHANGED <<owners, tokens, claimed, everTokenMintedBy>>

\* AuthzRPC.cleanupTenant: drop the tenant's authz data, ownership tuples and
\* service tokens (domain/sandbox delete, sandbox sweep). History variables
\* are unchanged.
Cleanup(t) ==
    /\ owners' = [owners EXCEPT ![t] = {}]
    /\ tokens' = [tokens EXCEPT ![t] = {}]
    /\ UNCHANGED <<claimed, everTokenMintedBy, mutators, everAuthorized>>

Next ==
    \/ \E t \in Tenants, u \in Users : Claim(t, u) \/ Mutate(t, u)
    \/ \E t \in Tenants, u \in Users, k \in TokenIds :
           MintToken(t, u, k) \/ RevokeToken(t, u, k)
    \/ \E t \in Tenants : MutateViaToken(t) \/ Cleanup(t)

Spec == Init /\ [][Next]_vars

TypeOK ==
    /\ owners \in [Tenants -> SUBSET Users]
    /\ tokens \in [Tenants -> SUBSET TokenIds]
    /\ claimed \subseteq Tenants \X Users
    /\ everTokenMintedBy \subseteq Tenants \X Users
    /\ mutators \subseteq Tenants \X Principals
    /\ everAuthorized \subseteq Tenants \X Principals

\* Ownership only ever comes from the trusted grant path.
OwnersWereClaimed ==
    \A t \in Tenants : \A u \in owners[t] : <<t, u>> \in claimed

\* Anonymous sandboxes are ownerless throwaway pools.
NoAnonOwners == \A t \in AnonSandbox : owners[t] = {}

\* Every gated mutation was authorized when it happened.
MutatorsWereAuthorized == mutators \subseteq everAuthorized

\* Every token mint was performed by a user owner-claimed on that tenant at
\* mint time (claimed is monotone, so membership now implies membership then).
TokensImplyOwnerMinted == everTokenMintedBy \subseteq claimed

\* Anonymous sandboxes can never hold service tokens.
NoAnonTokens == \A t \in AnonSandbox : tokens[t] = {}

\* Token mutations only ever happen on tenants whose owner minted a token.
TokenMutatorsHadMintedTokens ==
    \A t \in Tenants :
        <<t, svc>> \in mutators => \E u \in Users : <<t, u>> \in everTokenMintedBy

=============================================================================
