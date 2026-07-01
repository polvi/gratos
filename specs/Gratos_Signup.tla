--------------------------- MODULE Gratos_Signup ---------------------------
EXTENDS Naturals, TLC, FiniteSets

CONSTANTS
    Identities,     \* Set of possible identities (human, bot, service, etc.)
    Domains         \* Set of possible domain names

VARIABLES
    claims,         \* Set of [domain, identity, hasCfId] — pending_claims rows in D1.
                    \* identity = 0 means unbound (anonymous claim).
                    \* hasCfId: TRUE when cf_hostname_id has been written (= "activating").
    claimed,        \* Set of [domain, owner] — rows in domains table, at most one per domain.
    dns             \* Function Domains -> BOOLEAN
                    \* Models whether CNAME for authgravity.{d} points to cname.authgravity.net.
                    \* The implementation checks against a global target, not per-session.

ClaimRec == [domain: Domains, identity: Identities \cup {0}, hasCfId: BOOLEAN]

vars == <<claims, claimed, dns>>

\* --- Helpers ---

IsClaimed(d) == \E r \in claimed : r.domain = d

HasPendingClaim(d) ==
    \E r \in claims : r.domain = d

ClaimOf(d) ==
    CHOOSE r \in claims : r.domain = d

IsBound(d) ==
    \E r \in claims : r.domain = d /\ r.identity # 0

IdentityOfClaim(d) ==
    (CHOOSE r \in claims : r.domain = d).identity

HasCfId(d) ==
    \E r \in claims : r.domain = d /\ r.hasCfId

\* --- Type invariant ---

TypeOK ==
    /\ claims \subseteq ClaimRec
    /\ claimed \subseteq [domain: Domains, owner: Identities]
    /\ DOMAIN dns = Domains
    /\ \A d \in Domains : dns[d] \in BOOLEAN
    \* At most one pending claim per domain (implementation enforces this)
    /\ \A r1, r2 \in claims : r1.domain = r2.domain => r1 = r2
    \* At most one owner per domain
    /\ \A r1, r2 \in claimed : r1.domain = r2.domain => r1 = r2

Init ==
    /\ claims = {}
    /\ claimed = {}
    /\ dns = [d \in Domains |-> FALSE]

\* --- Actions ---

\* POST /claims — create pending claim (anonymous, no auth required).
\* One pending claim per domain. Domain must not be claimed.
\* In the implementation, if a pending claim already exists, 409 is returned
\* (unless the caller is the same identity, which we model separately).
EnterDomain(d) ==
    /\ ~IsClaimed(d)
    /\ ~HasPendingClaim(d)
    /\ claims' = claims \cup
        {[domain |-> d, identity |-> 0, hasCfId |-> FALSE]}
    /\ UNCHANGED <<claimed, dns>>

\* POST /claims when domain is already claimed by same identity — "reclaim" path.
\* Returns the existing domain record. No state change needed in the model
\* since the domain is already claimed. We model it as a no-op that is enabled
\* (proves the path exists without changing state).
\* Reclaim(id, d) ==
\*     /\ \E r \in claimed : r.domain = d /\ r.owner = id
\*     /\ UNCHANGED vars
\* (Commented out: no-op actions don't help TLC and just expand the state space.)

\* Identity binds to an anonymous claim via POST /claims/:id/activate.
\* In the implementation, the first activate call with auth binds identity_id.
BindIdentity(id, d) ==
    /\ HasPendingClaim(d)
    /\ (ClaimOf(d)).identity = 0
    /\ LET old == ClaimOf(d)
       IN claims' = (claims \ {old}) \cup
            {[domain |-> d, identity |-> id, hasCfId |-> old.hasCfId]}
    /\ UNCHANGED <<claimed, dns>>

\* External event: DNS owner sets CNAME for authgravity.{d} to point at
\* cname.authgravity.net (the global target).
SetDNS(d) ==
    /\ ~dns[d]
    /\ dns' = [dns EXCEPT ![d] = TRUE]
    /\ UNCHANGED <<claims, claimed>>

\* External event: DNS owner removes or changes CNAME away.
ClearDNS(d) ==
    /\ dns[d]
    /\ dns' = [dns EXCEPT ![d] = FALSE]
    /\ UNCHANGED <<claims, claimed>>

\* Domain Connect success callback: sets cf_hostname_id directly,
\* bypassing DNS check. This models the /domain-connect/callback redirect
\* followed by an activate call with skip_dns=true.
\* Requires auth (identity must be bound) since activate is auth-gated.
DomainConnectSuccess(d) ==
    /\ HasPendingClaim(d)
    /\ IsBound(d)
    /\ ~HasCfId(d)
    /\ LET old == ClaimOf(d)
       IN claims' = (claims \ {old}) \cup
            {[domain |-> d, identity |-> old.identity, hasCfId |-> TRUE]}
    /\ UNCHANGED <<claimed, dns>>

\* POST /claims/:id/activate — advance claim via DNS verification path.
\* If cf_hostname_id is NOT set and skip_dns is not true, DNS must be verified.
\* Creates CF custom hostname and sets hasCfId = TRUE.
\* Requires auth (identity bound).
ActivateDNS(d) ==
    /\ HasPendingClaim(d)
    /\ IsBound(d)
    /\ ~HasCfId(d)
    \* DNS must point to the global target
    /\ dns[d]
    /\ LET old == ClaimOf(d)
       IN claims' = (claims \ {old}) \cup
            {[domain |-> d, identity |-> old.identity, hasCfId |-> TRUE]}
    /\ UNCHANGED <<claimed, dns>>

\* POST /claims/:id/activate when cf_hostname_id is already set.
\* DNS check is skipped (line 148 of index.ts: !claim.cf_hostname_id guard).
\* CF hostname status becomes active, CNAME re-verified, domain claimed.
\* Models the final transition from "activating" to "claimed".
\* Can be triggered by user polling or by the scheduled handler.
FinalizeClaim(d) ==
    /\ HasPendingClaim(d)
    /\ IsBound(d)
    /\ HasCfId(d)
    /\ ~IsClaimed(d)
    \* Re-verify CNAME still points correctly (line 232-234 of index.ts)
    /\ dns[d]
    /\ LET id == IdentityOfClaim(d)
       IN claimed' = claimed \cup {[domain |-> d, owner |-> id]}
    \* Remove the pending claim for this domain
    /\ claims' = claims \ {r \in claims : r.domain = d}
    /\ UNCHANGED <<dns>>

\* Same-owner reclaim during advanceClaim (lines 220-228 of index.ts):
\* If we reach finalization but domain is already claimed by same identity,
\* just clean up the pending claim.
FinalizeReclaim(d) ==
    /\ HasPendingClaim(d)
    /\ IsBound(d)
    /\ HasCfId(d)
    /\ IsClaimed(d)
    /\ \E r \in claimed : r.domain = d /\ r.owner = IdentityOfClaim(d)
    /\ claims' = claims \ {r \in claims : r.domain = d}
    /\ UNCHANGED <<claimed, dns>>

\* Claim expires (4-hour TTL) or is cancelled via DELETE /claims/:id.
\* If the claim had a cf_hostname_id, the CF hostname is deleted too.
\* Also models the scheduled handler expiring stale claims.
ExpireClaim(d) ==
    /\ HasPendingClaim(d)
    /\ claims' = claims \ {ClaimOf(d)}
    /\ UNCHANGED <<claimed, dns>>

\* Race condition: activate called but claim was already advanced by
\* scheduled handler. The activate endpoint (lines 487-498) returns the
\* most recent domain for that identity. This is a read-only operation
\* in the implementation and doesn't change state, so we don't need
\* a separate action for it.

Next ==
    \/ \E d \in Domains : EnterDomain(d)
    \/ \E id \in Identities, d \in Domains : BindIdentity(id, d)
    \/ \E d \in Domains : SetDNS(d)
    \/ \E d \in Domains : ClearDNS(d)
    \/ \E d \in Domains : DomainConnectSuccess(d)
    \/ \E d \in Domains : ActivateDNS(d)
    \/ \E d \in Domains : FinalizeClaim(d)
    \/ \E d \in Domains : FinalizeReclaim(d)
    \/ \E d \in Domains : ExpireClaim(d)

Spec == Init /\ [][Next]_vars

\* --- Invariants ---

\* A claimed domain has no lingering pending claims
NoPendingAndClaimed ==
    \A d \in Domains : IsClaimed(d) =>
        ~\E r \in claims : r.domain = d

\* At most one owner per domain
OneDomainOneOwner ==
    \A r1, r2 \in claimed : r1.domain = r2.domain => r1 = r2

\* At most one pending claim per domain
OneDomainOneClaim ==
    \A r1, r2 \in claims : r1.domain = r2.domain => r1 = r2

\* A domain can only be claimed by a bound identity (not anonymous)
ClaimedByIdentity ==
    \A r \in claimed : r.owner \in Identities

\* If a claim has hasCfId=TRUE, it must be bound to an identity.
\* (Only ActivateDNS or DomainConnectSuccess can set hasCfId, both require IsBound.)
CfIdImpliesBound ==
    \A r \in claims : r.hasCfId => r.identity # 0

=============================================================================
