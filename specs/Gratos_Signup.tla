--------------------------- MODULE Gratos_Signup ---------------------------
EXTENDS Naturals, TLC, FiniteSets

CONSTANTS
    Identities,     \* Set of possible identities (human, bot, service, etc.)
    Domains         \* Set of possible domain names

VARIABLES
    sessions,       \* SUBSET Sessions — live session keys in KV
    authed,         \* Set of [session, identity] — which sessions have authenticated
    pendingClaims,  \* Set of [domain, session] — claim keys in KV
    claimed,        \* Set of [domain, owner] — permanent (no TTL)
    cfProvisioned,  \* SUBSET Domains — custom hostnames created in CF
    cfValidated     \* SUBSET Domains — CF has validated the domain

Sessions == 1..3

vars == <<sessions, authed, pendingClaims, claimed, cfProvisioned, cfValidated>>

\* --- Helpers ---

IsAuthed(s) == \E r \in authed : r.session = s
IsAnon(s) == s \in sessions /\ ~IsAuthed(s)
IdentityOf(s) == (CHOOSE r \in authed : r.session = s).identity

IsPending(d) == \E r \in pendingClaims : r.domain = d
IsClaimed(d) == \E r \in claimed : r.domain = d
IsAvailable(d) == ~IsPending(d) /\ ~IsClaimed(d)
ClaimOf(d) == CHOOSE r \in pendingClaims : r.domain = d

\* --- Type invariant ---

TypeOK ==
    /\ sessions \subseteq Sessions
    /\ authed \subseteq [session: Sessions, identity: Identities]
    /\ pendingClaims \subseteq [domain: Domains, session: Sessions]
    /\ claimed \subseteq [domain: Domains, owner: Identities]
    /\ cfProvisioned \subseteq Domains
    /\ cfValidated \subseteq Domains
    \* Functional dependencies
    /\ \A r1, r2 \in authed : r1.session = r2.session => r1 = r2
    /\ \A r1, r2 \in pendingClaims : r1.domain = r2.domain => r1 = r2
    /\ \A r1, r2 \in claimed : r1.domain = r2.domain => r1 = r2

Init ==
    /\ sessions = Sessions
    /\ authed = {}
    /\ pendingClaims = {}
    /\ claimed = {}
    /\ cfProvisioned = {}
    /\ cfValidated = {}

\* --- Actions ---

\* Anonymous session enters a domain name, starting a pending claim.
EnterDomain(s, d) ==
    /\ IsAnon(s)
    /\ IsAvailable(d)
    /\ pendingClaims' = pendingClaims \cup {[domain |-> d, session |-> s]}
    /\ UNCHANGED <<sessions, authed, claimed, cfProvisioned, cfValidated>>

\* Identity authenticates with a passkey.
Authenticate(s, id) ==
    /\ IsAnon(s)
    /\ authed' = authed \cup {[session |-> s, identity |-> id]}
    /\ UNCHANGED <<sessions, pendingClaims, claimed, cfProvisioned, cfValidated>>

\* Authenticated session provisions a custom hostname in CF.
\* Requires: authenticated, has a pending claim for this domain,
\* and the domain is not already provisioned.
ProvisionCF(s, d) ==
    /\ IsPending(d)
    /\ ClaimOf(d).session = s
    /\ IsAuthed(s)
    /\ d \notin cfProvisioned
    /\ cfProvisioned' = cfProvisioned \cup {d}
    /\ UNCHANGED <<sessions, authed, pendingClaims, claimed, cfValidated>>

\* External event: CF validates the domain (DNS resolves, TLS issued, etc.)
\* This is CF's source of truth — we don't check DNS ourselves.
ValidateCF(d) ==
    /\ d \in cfProvisioned
    /\ d \notin cfValidated
    /\ cfValidated' = cfValidated \cup {d}
    /\ UNCHANGED <<sessions, authed, pendingClaims, claimed, cfProvisioned>>

\* Claim a domain. Requires: authenticated, CF has validated,
\* and session matches the pending claim.
ClaimDomain(s, d) ==
    /\ IsPending(d)
    /\ ClaimOf(d).session = s
    /\ IsAuthed(s)
    /\ d \in cfValidated
    /\ claimed' = claimed \cup {[domain |-> d, owner |-> IdentityOf(s)]}
    /\ pendingClaims' = pendingClaims \ {ClaimOf(d)}
    /\ UNCHANGED <<sessions, authed, cfProvisioned, cfValidated>>

\* KV TTL fires — session key disappears.
\* Auth metadata goes with it (same key).
ExpireSession(s) ==
    /\ s \in sessions
    /\ sessions' = sessions \ {s}
    /\ authed' = authed \ {r \in authed : r.session = s}
    /\ UNCHANGED <<pendingClaims, claimed, cfProvisioned, cfValidated>>

\* KV TTL fires — claim key disappears.
\* We must also clean up the CF resource if one was provisioned.
ExpireClaim(d) ==
    /\ IsPending(d)
    /\ pendingClaims' = pendingClaims \ {ClaimOf(d)}
    /\ cfProvisioned' = cfProvisioned \ {d}
    /\ cfValidated' = cfValidated \ {d}
    /\ UNCHANGED <<sessions, authed, claimed>>

Next ==
    \/ \E s \in Sessions, d \in Domains : EnterDomain(s, d)
    \/ \E s \in Sessions, id \in Identities : Authenticate(s, id)
    \/ \E s \in Sessions, d \in Domains : ProvisionCF(s, d)
    \/ \E d \in Domains : ValidateCF(d)
    \/ \E s \in Sessions, d \in Domains : ClaimDomain(s, d)
    \/ \E s \in Sessions : ExpireSession(s)
    \/ \E d \in Domains : ExpireClaim(d)

Spec == Init /\ [][Next]_vars

\* --- Invariants ---

\* Auth metadata only exists for live sessions
AuthedImpliesLiveSession ==
    \A r \in authed : r.session \in sessions

\* A domain cannot be both pending and claimed
NoPendingAndClaimed ==
    \A d \in Domains : ~(IsPending(d) /\ IsClaimed(d))

\* CF validation implies CF provisioned
ValidatedImpliesProvisioned ==
    cfValidated \subseteq cfProvisioned

\* No orphaned CF resources: every provisioned domain is either
\* pending (mid-claim) or claimed (completed)
NoOrphanedCFResources ==
    \A d \in cfProvisioned : IsPending(d) \/ IsClaimed(d)

\* A claimed domain has a validated CF resource backing it
ClaimedImpliesCFValidated ==
    \A r \in claimed : r.domain \in cfValidated

=============================================================================
