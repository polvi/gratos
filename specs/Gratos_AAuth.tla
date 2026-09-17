--------------------------- MODULE Gratos_AAuth ----------------------------
(***************************************************************************)
(* AAuth Person Server consent/mission state machines in gratos-multi      *)
(* (packages/gratos-multi/src/aauth/{missions,pending,routes}.ts).         *)
(*                                                                         *)
(* Two pending stores, modeled per the implementation:                     *)
(*                                                                         *)
(* 1. MISSIONS (D1 aauth_missions — consent can wait days). Lifecycle:     *)
(*    proposed -> active (consent approve) | declined (consent deny)       *)
(*             | expired (TTL sweep / lazy effectiveStatus / agent DELETE) *)
(*    active   -> completed (accepted completion interaction; the SQL      *)
(*                closeMission guard is WHERE status='active')             *)
(*             | revoked (user kill-switch; only row.user_id = approver)   *)
(*    All of completed/declined/revoked/expired are terminal.              *)
(*    The consent code (code_hash) is minted at propose and cleared        *)
(*    (SET code_hash = NULL) by every transition out of 'proposed', so a   *)
(*    code resolves at most one final decision. A proposal may name an     *)
(*    intended approver (approver_hint); requireIntendedApprover rejects   *)
(*    consent by anyone else with no state change — modeled by simply not  *)
(*    enabling Approve/Decline for other users.                            *)
(*    Budgets: consent-time attenuation (applyAttenuation) may only        *)
(*    NARROW — per-resource granted amount <= proposed amount, entries may *)
(*    be omitted (granted 0), never added (granted > 0 needs proposed >    *)
(*    0). Amounts are 0..MaxAmt; 0 encodes "no entry for this resource".   *)
(*    Budget-path token issuance (POST /v1/aauth/token with a mission ref) *)
(*    calls requireActiveMission: it mints ONLY while the mission is       *)
(*    active; after revoke/complete/expire the agent gets a distinct       *)
(*    error and no token (mission-bound permission requests are gated the  *)
(*    same way) — modeled as MintBudgetToken recording the status at mint. *)
(*                                                                         *)
(* 2. KV PENDINGS (aauth_pending — token/permission/interaction, 600s      *)
(*    TTL). pending -> approved (consent approve; for kind=token the auth  *)
(*    token is minted ONCE into pending.result) | denied | gone (TTL).     *)
(*    The consent code mapping is consumed (consumeCode) on either         *)
(*    decision; the code key can also TTL out on its own while the record  *)
(*    lives (putPending refreshes the record TTL, never the code's).       *)
(*    The agent's poll (GET /v1/aauth/pending/:id) is a one-shot pickup:   *)
(*    it deletes the record before returning the result, so an approved    *)
(*    result is delivered at most once.                                    *)
(*                                                                         *)
(* Checked properties:                                                     *)
(*   TypeOK                                                                *)
(*   CodeSingleUse      — a mission code resolves at most one final        *)
(*                        decision; codes are cleared whenever the record  *)
(*                        leaves its awaiting-consent state.               *)
(*   ApproverBinding    — a decided mission (active/declined/completed/    *)
(*                        revoked) with a named intended approver was      *)
(*                        decided by exactly that user.                    *)
(*   AttenuationNeverWidens — for every activated mission, granted[r] <=   *)
(*                        proposed[r] for all resources (covers both       *)
(*                        amount narrowing and entries-subset), and        *)
(*                        never-activated missions grant nothing.          *)
(*   NoIssuanceAfterClose — every budget-path token mint happened while    *)
(*                        the mission was 'active'.                        *)
(*   OneShotPickup      — a KV pending mints at most one token and its     *)
(*                        result is delivered at most once (and only if    *)
(*                        minted).                                         *)
(*   ClosedIsTerminal / GoneIsTerminal (temporal) — closed missions and    *)
(*                        deleted pendings never change state again.       *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets

CONSTANTS
    Users,       \* passkey-session users of the tenant (potential approvers)
    MissionIds,  \* pool of D1 mission rows
    PendingIds,  \* pool of KV pending records
    Resources,   \* budget resource URLs
    MaxAmt,      \* budget amounts are 0..MaxAmt (0 = no entry)
    NoUser       \* "no approver_hint" / "not decided" marker

ASSUME NoUser \notin Users
ASSUME MaxAmt \in Nat \ {0}

MStatuses == {"none", "proposed", "active", "completed", "declined", "revoked", "expired"}
MClosed   == {"completed", "declined", "revoked", "expired"}
Activated == {"active", "completed", "revoked"}   \* passed through approve
PStatuses == {"none", "pending", "approved", "denied", "gone"}

Budgets    == [Resources -> 0..MaxAmt]
ZeroBudget == [r \in Resources |-> 0]

VARIABLES
    \* -- missions (D1 row per id) --
    mStatus,    \* [MissionIds -> MStatuses] ("none" = row not yet inserted)
    mHint,      \* [MissionIds -> Users \cup {NoUser}] approver_hint
    mCode,      \* [MissionIds -> BOOLEAN] consent code_hash still set
    mProposed,  \* [MissionIds -> Budgets] proposal_json budgets
    mGranted,   \* [MissionIds -> Budgets] mission_json (approved) budgets
    mBy,        \* [MissionIds -> Users \cup {NoUser}] user_id (decider)
    mDecisions, \* [MissionIds -> 0..2] final decisions resolved via the code
    mMintedAt,  \* [MissionIds -> SUBSET MStatuses] statuses at budget mints
    \* -- KV pendings --
    pStatus,    \* [PendingIds -> PStatuses]
    pCode,      \* [PendingIds -> BOOLEAN] aauth_code key still live
    pMinted,    \* [PendingIds -> 0..2] tokens minted into pending.result
    pDelivered  \* [PendingIds -> 0..2] one-shot pickups that returned it

missionVars == <<mStatus, mHint, mCode, mProposed, mGranted, mBy, mDecisions, mMintedAt>>
pendingVars == <<pStatus, pCode, pMinted, pDelivered>>
vars == <<missionVars, pendingVars>>

Init ==
    /\ mStatus    = [m \in MissionIds |-> "none"]
    /\ mHint      = [m \in MissionIds |-> NoUser]
    /\ mCode      = [m \in MissionIds |-> FALSE]
    /\ mProposed  = [m \in MissionIds |-> ZeroBudget]
    /\ mGranted   = [m \in MissionIds |-> ZeroBudget]
    /\ mBy        = [m \in MissionIds |-> NoUser]
    /\ mDecisions = [m \in MissionIds |-> 0]
    /\ mMintedAt  = [m \in MissionIds |-> {}]
    /\ pStatus    = [p \in PendingIds |-> "none"]
    /\ pCode      = [p \in PendingIds |-> FALSE]
    /\ pMinted    = [p \in PendingIds |-> 0]
    /\ pDelivered = [p \in PendingIds |-> 0]

(* ---------------------------- Missions -------------------------------- *)

\* POST /v1/aauth/mission (proposeMission): row inserted status='proposed'
\* with a fresh single-use code; the agent picks any approver hint and
\* budget proposal.
Propose(m, hint, b) ==
    /\ mStatus[m] = "none"
    /\ mStatus'   = [mStatus EXCEPT ![m] = "proposed"]
    /\ mHint'     = [mHint EXCEPT ![m] = hint]
    /\ mCode'     = [mCode EXCEPT ![m] = TRUE]
    /\ mProposed' = [mProposed EXCEPT ![m] = b]
    /\ UNCHANGED <<mGranted, mBy, mDecisions, mMintedAt, pendingVars>>

\* POST /v1/aauth/consent decision=approve (resolveCode requires the code
\* and effectiveStatus='proposed'; requireIntendedApprover gates u;
\* applyAttenuation admits only narrowing). approveMission: status='active',
\* user_id=u, code_hash=NULL.
Approve(m, u, g) ==
    /\ mStatus[m] = "proposed"
    /\ mCode[m]
    /\ mHint[m] \in {NoUser, u}
    /\ \A r \in Resources : g[r] <= mProposed[m][r]
    /\ mStatus'    = [mStatus EXCEPT ![m] = "active"]
    /\ mCode'      = [mCode EXCEPT ![m] = FALSE]
    /\ mGranted'   = [mGranted EXCEPT ![m] = g]
    /\ mBy'        = [mBy EXCEPT ![m] = u]
    /\ mDecisions' = [mDecisions EXCEPT ![m] = @ + 1]
    /\ UNCHANGED <<mHint, mProposed, mMintedAt, pendingVars>>

\* POST /v1/aauth/consent decision=deny (declineMission): status='declined',
\* user_id=u, code_hash=NULL.
Decline(m, u) ==
    /\ mStatus[m] = "proposed"
    /\ mCode[m]
    /\ mHint[m] \in {NoUser, u}
    /\ mStatus'    = [mStatus EXCEPT ![m] = "declined"]
    /\ mCode'      = [mCode EXCEPT ![m] = FALSE]
    /\ mBy'        = [mBy EXCEPT ![m] = u]
    /\ mDecisions' = [mDecisions EXCEPT ![m] = @ + 1]
    /\ UNCHANGED <<mHint, mProposed, mGranted, mMintedAt, pendingVars>>

\* Proposal window ends: lazy effectiveStatus, the cron expireSweep, or the
\* agent cancelling via DELETE /v1/aauth/pending/:id — all run the same
\* UPDATE ... SET status='expired', code_hash=NULL WHERE status='proposed'.
ExpireProposal(m) ==
    /\ mStatus[m] = "proposed"
    /\ mStatus' = [mStatus EXCEPT ![m] = "expired"]
    /\ mCode'   = [mCode EXCEPT ![m] = FALSE]
    /\ UNCHANGED <<mHint, mProposed, mGranted, mBy, mDecisions, mMintedAt, pendingVars>>

\* Accepted completion interaction: closeMission(id,'completed') with the
\* SQL guard WHERE status='active' (a revoked mission stays revoked).
Complete(m) ==
    /\ mStatus[m] = "active"
    /\ mStatus' = [mStatus EXCEPT ![m] = "completed"]
    /\ UNCHANGED <<mHint, mCode, mProposed, mGranted, mBy, mDecisions, mMintedAt, pendingVars>>

\* POST /v1/aauth/missions/:id/revoke: kill-switch, only for the session
\* user who approved (row.user_id = userId), only while active.
Revoke(m, u) ==
    /\ mStatus[m] = "active"
    /\ mBy[m] = u
    /\ mStatus' = [mStatus EXCEPT ![m] = "revoked"]
    /\ UNCHANGED <<mHint, mCode, mProposed, mGranted, mBy, mDecisions, mMintedAt, pendingVars>>

\* Budget path of POST /v1/aauth/token (and, identically gated,
\* mission-bound POST /v1/aauth/permission): requireActiveMission, then a
\* granted budget entry for the resource => mint. We record the mission
\* status observed at mint time; the request is modeled as atomic.
MintBudgetToken(m) ==
    /\ mStatus[m] = "active"
    /\ \E r \in Resources : mGranted[m][r] > 0
    /\ mMintedAt' = [mMintedAt EXCEPT ![m] = @ \cup {mStatus[m]}]
    /\ UNCHANGED <<mStatus, mHint, mCode, mProposed, mGranted, mBy, mDecisions, pendingVars>>

(* --------------------------- KV pendings ------------------------------ *)

\* createPending: record + code key written, both TTL 600s.
CreatePending(p) ==
    /\ pStatus[p] = "none"
    /\ pStatus' = [pStatus EXCEPT ![p] = "pending"]
    /\ pCode'   = [pCode EXCEPT ![p] = TRUE]
    /\ UNCHANGED <<pMinted, pDelivered, missionVars>>

\* Consent approve: consumeCode, mint the auth token into pending.result
\* (kind=token; other kinds store their result the same way), st='approved'.
ApprovePending(p) ==
    /\ pStatus[p] = "pending"
    /\ pCode[p]
    /\ pStatus' = [pStatus EXCEPT ![p] = "approved"]
    /\ pCode'   = [pCode EXCEPT ![p] = FALSE]
    /\ pMinted' = [pMinted EXCEPT ![p] = @ + 1]
    /\ UNCHANGED <<pDelivered, missionVars>>

\* Consent deny: consumeCode, st='denied', no token.
DenyPending(p) ==
    /\ pStatus[p] = "pending"
    /\ pCode[p]
    /\ pStatus' = [pStatus EXCEPT ![p] = "denied"]
    /\ pCode'   = [pCode EXCEPT ![p] = FALSE]
    /\ UNCHANGED <<pMinted, pDelivered, missionVars>>

\* GET /v1/aauth/pending/:id on a resolved record: deletePending BEFORE
\* returning the result — one-shot pickup (approved delivers the token;
\* denied delivers the 403).
PickupPending(p) ==
    /\ pStatus[p] \in {"approved", "denied"}
    /\ pStatus'    = [pStatus EXCEPT ![p] = "gone"]
    /\ pDelivered' = [pDelivered EXCEPT ![p] = IF pStatus[p] = "approved" THEN @ + 1 ELSE @]
    /\ UNCHANGED <<pCode, pMinted, missionVars>>

\* KV TTL on the record (or agent DELETE): the record vanishes, resolved or
\* not; an un-picked-up approved result is lost.
ExpirePending(p) ==
    /\ pStatus[p] \in {"pending", "approved", "denied"}
    /\ pStatus' = [pStatus EXCEPT ![p] = "gone"]
    /\ pCode'   = [pCode EXCEPT ![p] = FALSE]
    /\ UNCHANGED <<pMinted, pDelivered, missionVars>>

\* KV TTL on the code key alone: putPending refreshes the record's TTL but
\* never the code's, so the code can die first; the record then sits
\* undecidable until its own TTL.
ExpirePendingCode(p) ==
    /\ pStatus[p] = "pending"
    /\ pCode[p]
    /\ pCode' = [pCode EXCEPT ![p] = FALSE]
    /\ UNCHANGED <<pStatus, pMinted, pDelivered, missionVars>>

Next ==
    \/ \E m \in MissionIds :
        \/ \E hint \in Users \cup {NoUser} : \E b \in Budgets : Propose(m, hint, b)
        \/ \E u \in Users :
            \/ \E g \in Budgets : Approve(m, u, g)
            \/ Decline(m, u)
            \/ Revoke(m, u)
        \/ ExpireProposal(m)
        \/ Complete(m)
        \/ MintBudgetToken(m)
    \/ \E p \in PendingIds :
        \/ CreatePending(p)
        \/ ApprovePending(p)
        \/ DenyPending(p)
        \/ PickupPending(p)
        \/ ExpirePending(p)
        \/ ExpirePendingCode(p)

Spec == Init /\ [][Next]_vars

(* --------------------------- Properties ------------------------------- *)

TypeOK ==
    /\ mStatus    \in [MissionIds -> MStatuses]
    /\ mHint      \in [MissionIds -> Users \cup {NoUser}]
    /\ mCode      \in [MissionIds -> BOOLEAN]
    /\ mProposed  \in [MissionIds -> Budgets]
    /\ mGranted   \in [MissionIds -> Budgets]
    /\ mBy        \in [MissionIds -> Users \cup {NoUser}]
    /\ mDecisions \in [MissionIds -> 0..2]
    /\ mMintedAt  \in [MissionIds -> SUBSET MStatuses]
    /\ pStatus    \in [PendingIds -> PStatuses]
    /\ pCode      \in [PendingIds -> BOOLEAN]
    /\ pMinted    \in [PendingIds -> 0..2]
    /\ pDelivered \in [PendingIds -> 0..2]

\* A consent code resolves at most one final decision, because every
\* transition out of the awaiting state clears it (mission: code_hash=NULL;
\* pending: consumeCode / TTL).
CodeSingleUse ==
    /\ \A m \in MissionIds :
        /\ mDecisions[m] <= 1
        /\ mStatus[m] # "proposed" => ~mCode[m]
    /\ \A p \in PendingIds :
        pStatus[p] # "pending" => ~pCode[p]

\* A proposal naming an intended approver was decided by exactly that user.
ApproverBinding ==
    \A m \in MissionIds :
        mStatus[m] \in {"active", "completed", "revoked", "declined"} =>
            mHint[m] \in {NoUser, mBy[m]}

\* Attenuation never widens: granted <= proposed per resource (covers both
\* the amount rule and entries-subset, 0 = entry absent), and a mission
\* that never activated grants nothing.
AttenuationNeverWidens ==
    \A m \in MissionIds :
        IF mStatus[m] \in Activated
        THEN \A r \in Resources : mGranted[m][r] <= mProposed[m][r]
        ELSE mGranted[m] = ZeroBudget

\* Every budget-path issuance happened while the mission was active: after
\* revoke/complete/expire the agent gets mission_revoked / mission_completed
\* / mission_expired and no token.
NoIssuanceAfterClose ==
    \A m \in MissionIds : mMintedAt[m] \subseteq {"active"}

\* A KV pending mints at most one token, and the one-shot pickup delivers a
\* result at most once — and only ever a minted one.
OneShotPickup ==
    \A p \in PendingIds :
        /\ pMinted[p] <= 1
        /\ pDelivered[p] <= 1
        /\ pDelivered[p] <= pMinted[p]

\* Closed missions and deleted pendings are terminal.
ClosedIsTerminal ==
    [][\A m \in MissionIds : mStatus[m] \in MClosed => mStatus'[m] = mStatus[m]]_vars

GoneIsTerminal ==
    [][\A p \in PendingIds : pStatus[p] = "gone" => pStatus'[p] = "gone"]_vars

=============================================================================
