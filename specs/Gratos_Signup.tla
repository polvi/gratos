--------------------------- MODULE Gratos_Signup ---------------------------
EXTENDS Naturals, TLC, FiniteSets

CONSTANTS
    Identities,     \* Set of possible identities (human, bot, service, etc.)
    Domains         \* Set of possible domain names

VARIABLES
    sessions,       \* SUBSET Sessions — live session keys in KV
    authed,         \* Set of [session, identity] — which sessions have authenticated
    pendingClaims,  \* Set of [domain, session] — claim keys in KV (multiple per domain OK)
    claimed,        \* Set of [domain, owner] — permanent (no TTL), at most one per domain
    cfProvisioned,  \* SUBSET Domains — CF custom hostname letsident.{d} exists
    cfValidated     \* Set of [domain, session] — CNAME target matches this claim's token
                    \* At most one per domain (DNS CNAME is single-valued)

Sessions == 1..3

ClaimRec == [domain: Domains, session: Sessions]

vars == <<sessions, authed, pendingClaims, claimed, cfProvisioned, cfValidated>>

\* --- Helpers ---

IsAuthed(s) == \E r \in authed : r.session = s
IsAnon(s) == s \in sessions /\ ~IsAuthed(s)
IdentityOf(s) == (CHOOSE r \in authed : r.session = s).identity

IsClaimed(d) == \E r \in claimed : r.domain = d
HasPendingClaim(s, d) == [domain |-> d, session |-> s] \in pendingClaims

\* --- Type invariant ---

TypeOK ==
    /\ sessions \subseteq Sessions
    /\ authed \subseteq [session: Sessions, identity: Identities]
    /\ pendingClaims \subseteq ClaimRec
    /\ claimed \subseteq [domain: Domains, owner: Identities]
    /\ cfProvisioned \subseteq Domains
    /\ cfValidated \subseteq ClaimRec
    \* Functional dependencies
    /\ \A r1, r2 \in authed : r1.session = r2.session => r1 = r2
    /\ \A r1, r2 \in claimed : r1.domain = r2.domain => r1 = r2
    \* DNS CNAME is single-valued: at most one validated claim per domain
    /\ \A r1, r2 \in cfValidated : r1.domain = r2.domain => r1 = r2

Init ==
    /\ sessions = Sessions
    /\ authed = {}
    /\ pendingClaims = {}
    /\ claimed = {}
    /\ cfProvisioned = {}
    /\ cfValidated = {}

\* --- Actions ---

\* Session enters a domain name, starting a pending claim.
\* Multiple sessions can claim the same domain concurrently.
\* Each gets a unique CNAME target ({token}.cname.letsident.net).
\* The CF hostname is always letsident.{domain} (stable).
EnterDomain(s, d) ==
    /\ s \in sessions
    /\ ~IsClaimed(d)
    /\ ~HasPendingClaim(s, d)
    /\ pendingClaims' = pendingClaims \cup {[domain |-> d, session |-> s]}
    /\ UNCHANGED <<sessions, authed, claimed, cfProvisioned, cfValidated>>

\* Identity authenticates with a passkey.
Authenticate(s, id) ==
    /\ IsAnon(s)
    /\ authed' = authed \cup {[session |-> s, identity |-> id]}
    /\ UNCHANGED <<sessions, pendingClaims, claimed, cfProvisioned, cfValidated>>

\* External event: DNS owner sets CNAME target to a specific claim's token.
\* letsident.{d} CNAME {token}.cname.letsident.net
\* Since DNS CNAME is single-valued, this replaces any previous validation.
\* Only the DNS owner can set this, so it proves domain control.
\* DNS happens independently — no CF provisioning required yet.
ValidateDNS(s, d) ==
    /\ HasPendingClaim(s, d)
    \* Replace any existing validation for this domain (CNAME is single-valued)
    /\ cfValidated' = (cfValidated \ {r \in cfValidated : r.domain = d})
                       \cup {[domain |-> d, session |-> s]}
    /\ UNCHANGED <<sessions, authed, pendingClaims, claimed, cfProvisioned>>

\* Authenticated session provisions CF custom hostname letsident.{domain}.
\* Only happens AFTER DNS CNAME is verified for this claim.
\* The CF hostname is shared across all claims for the same domain.
\* If already provisioned, this is a no-op (idempotent).
ProvisionCF(s, d) ==
    /\ HasPendingClaim(s, d)
    /\ IsAuthed(s)
    /\ [domain |-> d, session |-> s] \in cfValidated
    /\ d \notin cfProvisioned
    /\ cfProvisioned' = cfProvisioned \cup {d}
    /\ UNCHANGED <<sessions, authed, pendingClaims, claimed, cfValidated>>

\* Claim a domain. Requires: authenticated, DNS validated, CF provisioned,
\* and domain not yet claimed by anyone.
\* On success: removes ALL pending claims for this domain and cleans up losers.
ClaimDomain(s, d) ==
    /\ HasPendingClaim(s, d)
    /\ IsAuthed(s)
    /\ [domain |-> d, session |-> s] \in cfValidated
    /\ d \in cfProvisioned
    /\ ~IsClaimed(d)
    /\ claimed' = claimed \cup {[domain |-> d, owner |-> IdentityOf(s)]}
    \* Remove all pending claims for this domain
    /\ pendingClaims' = pendingClaims \ {r \in pendingClaims : r.domain = d}
    \* Winner's CF hostname stays; validation records cleaned up
    /\ cfValidated' = cfValidated \ {r \in cfValidated : r.domain = d}
    /\ UNCHANGED <<sessions, authed, cfProvisioned>>

\* KV TTL fires — session key disappears.
\* Auth metadata goes with it (same key).
ExpireSession(s) ==
    /\ s \in sessions
    /\ sessions' = sessions \ {s}
    /\ authed' = authed \ {r \in authed : r.session = s}
    /\ UNCHANGED <<pendingClaims, claimed, cfProvisioned, cfValidated>>

\* KV TTL fires — a specific claim expires.
\* If this was the last claim for this domain, clean up CF hostname too.
ExpireClaim(s, d) ==
    /\ HasPendingClaim(s, d)
    /\ pendingClaims' = pendingClaims \ {[domain |-> d, session |-> s]}
    /\ cfValidated' = cfValidated \ {[domain |-> d, session |-> s]}
    \* Clean up CF hostname if no more pending claims for this domain
    /\ LET remaining == {r \in pendingClaims : r.domain = d /\ r.session # s}
       IN IF remaining = {}
          THEN cfProvisioned' = cfProvisioned \ {d}
          ELSE cfProvisioned' = cfProvisioned
    /\ UNCHANGED <<sessions, authed, claimed>>

Next ==
    \/ \E s \in Sessions, d \in Domains : EnterDomain(s, d)
    \/ \E s \in Sessions, id \in Identities : Authenticate(s, id)
    \/ \E s \in Sessions, d \in Domains : ValidateDNS(s, d)
    \/ \E s \in Sessions, d \in Domains : ProvisionCF(s, d)
    \/ \E s \in Sessions, d \in Domains : ClaimDomain(s, d)
    \/ \E s \in Sessions : ExpireSession(s)
    \/ \E s \in Sessions, d \in Domains : ExpireClaim(s, d)

Spec == Init /\ [][Next]_vars

\* --- Invariants ---

\* Auth metadata only exists for live sessions
AuthedImpliesLiveSession ==
    \A r \in authed : r.session \in sessions

\* A claimed domain has no lingering pending claims
NoPendingAndClaimed ==
    \A d \in Domains : IsClaimed(d) =>
        ~\E r \in pendingClaims : r.domain = d

\* No orphaned CF resources: every provisioned domain is either
\* pending (mid-claim) or claimed (completed)
NoOrphanedCFResources ==
    \A d \in cfProvisioned :
        (\E r \in pendingClaims : r.domain = d) \/ IsClaimed(d)

\* A claimed domain has a CF hostname backing it
ClaimedImpliesCFProvisioned ==
    \A r \in claimed : r.domain \in cfProvisioned

\* At most one owner per domain — two admins who both set valid CNAMEs
\* cannot both claim the same domain
OneDomainOneOwner ==
    \A r1, r2 \in claimed : r1.domain = r2.domain => r1 = r2

\* DNS CNAME is single-valued: at most one validated claim per domain
SingleCNAMEPerDomain ==
    \A r1, r2 \in cfValidated : r1.domain = r2.domain => r1 = r2

=============================================================================
