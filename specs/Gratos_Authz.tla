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
(* AuthzRPC.cleanupTenant (Cleanup) deletes a tenant's authz data and its  *)
(* ownership tuples on domain/sandbox delete and sandbox sweep; it refuses *)
(* the root tenant (the root tenant is simply not in Tenants here). The    *)
(* cron reconcile re-grants missing owner tuples from the source-of-truth  *)
(* tables — since grants are idempotent and Claim may fire repeatedly,     *)
(* reconcile is just Claim firing again.                                   *)
(*                                                                         *)
(* Checked properties:                                                     *)
(*   TypeOK                                                                *)
(*   OwnersWereClaimed      — every current owner pair came from the       *)
(*                            trusted grant path (no other source of       *)
(*                            ownership exists).                           *)
(*   NoAnonOwners           — anonymous sandbox tenants never have owners. *)
(*   MutatorsWereAuthorized — every gated mutation was performed by a user *)
(*                            authorized at the time: owner of the tenant, *)
(*                            or the tenant is an anonymous sandbox.       *)
(***************************************************************************)
EXTENDS FiniteSets

CONSTANTS
    Users,
    Tenants,
    AnonSandbox \* anonymous sandbox tenants (subset of Tenants)

ASSUME AnonSandbox \subseteq Tenants

VARIABLES
    owners,        \* current gratos_tenant:<t>#owner@user:<u> tuples, per tenant
    claimed,       \* history: <<t,u>> pairs ever granted via the trusted path
    mutators,      \* history: <<t,u>> such that u performed a gated mutation on t
    everAuthorized \* history: <<t,u>> authorized at some point (owner then, or anon sandbox)

vars == <<owners, claimed, mutators, everAuthorized>>

Init ==
    /\ owners = [t \in Tenants |-> {}]
    /\ claimed = {}
    /\ mutators = {}
    /\ everAuthorized = {}

\* Trusted onboarding grant (provisioner domain claim / owned-sandbox mint
\* calling AuthzRPC.grantTenantOwners). Idempotent — may fire repeatedly,
\* which also models the cron reconcile re-granting from source of truth.
Claim(t, u) ==
    /\ t \notin AnonSandbox
    /\ owners' = [owners EXCEPT ![t] = @ \cup {u}]
    /\ claimed' = claimed \cup {<<t, u>>}
    /\ UNCHANGED <<mutators, everAuthorized>>

\* Gated schema/tuple mutation: tenant owner via on-behalf routes, or any
\* authenticated user when the tenant is an anonymous (open) sandbox.
Mutate(t, u) ==
    /\ u \in owners[t] \/ t \in AnonSandbox
    /\ mutators' = mutators \cup {<<t, u>>}
    /\ everAuthorized' = everAuthorized \cup {<<t, u>>}
    /\ UNCHANGED <<owners, claimed>>

\* AuthzRPC.cleanupTenant: drop the tenant's authz data and ownership tuples
\* (domain/sandbox delete, sandbox sweep). History variables are unchanged.
Cleanup(t) ==
    /\ owners' = [owners EXCEPT ![t] = {}]
    /\ UNCHANGED <<claimed, mutators, everAuthorized>>

Next ==
    \/ \E t \in Tenants, u \in Users : Claim(t, u) \/ Mutate(t, u)
    \/ \E t \in Tenants : Cleanup(t)

Spec == Init /\ [][Next]_vars

TypeOK ==
    /\ owners \in [Tenants -> SUBSET Users]
    /\ claimed \subseteq Tenants \X Users
    /\ mutators \subseteq Tenants \X Users
    /\ everAuthorized \subseteq Tenants \X Users

\* Ownership only ever comes from the trusted grant path.
OwnersWereClaimed ==
    \A t \in Tenants : \A u \in owners[t] : <<t, u>> \in claimed

\* Anonymous sandboxes are ownerless throwaway pools.
NoAnonOwners == \A t \in AnonSandbox : owners[t] = {}

\* Every gated mutation was authorized when it happened.
MutatorsWereAuthorized == mutators \subseteq everAuthorized

=============================================================================
