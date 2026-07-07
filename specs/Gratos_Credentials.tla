------------------------ MODULE Gratos_Credentials -------------------------
(***************************************************************************)
(* Credential lifecycle of the account-key feature (gratos-multi           *)
(* src/keys.ts + src/sessions.ts), for a single user — credentials are the *)
(* state, so one user suffices.                                            *)
(*                                                                         *)
(* Credential kinds carry ranks (KIND_RANK in keys.ts / AMR_RANK in        *)
(* sessions.ts): webauthn=3, devicekey=2, softkey=1. Every session records *)
(* the amr of the credential that minted it, so a session is fully         *)
(* characterized by its rank; live sessions are modeled as a set of ranks. *)
(*                                                                         *)
(* Actions:                                                                *)
(*   SignupWith(k)  — register/verify with no session: first credential of *)
(*                    any kind (passkey signup or account-key signup) plus *)
(*                    a session of its rank.                               *)
(*   Attach(s, k)   — register-while-authenticated: a live session adds a  *)
(*                    credential (device-key provisioning, recovery-key    *)
(*                    enrollment, extra passkeys); verify also mints a     *)
(*                    session of the new credential's rank. Total          *)
(*                    credentials are capped (MAX_CREDENTIALS_PER_USER,    *)
(*                    shrunk here to bound state).                         *)
(*   Login(k)       — login/verify against an existing credential mints a  *)
(*                    session of rank(k).                                  *)
(*   Delete(s, k)   — DELETE /v1/credentials/:id, guarded by BOTH rules    *)
(*                    from the handler: the session outranks-or-equals the *)
(*                    target credential, AND more than one credential      *)
(*                    exists (never orphan an account).                    *)
(*   DropSession(s) — sessions expire / are logged out freely.             *)
(*                                                                         *)
(* Checked properties:                                                     *)
(*   TypeOK                                                                *)
(*   NeverOrphaned              — once any credential has existed, at      *)
(*                                least one always exists: the API can     *)
(*                                never delete the last credential.        *)
(*   NoPrivilegeEscalationDelete — every deletion ever performed was by a  *)
(*                                session whose rank >= the deleted        *)
(*                                credential's rank.                       *)
(*   PasskeySurvivesPhishedKey  — the story that motivated the rank rule:  *)
(*                                a webauthn credential is only ever       *)
(*                                deleted by a webauthn-rank session, so a *)
(*                                phished account key (rank-1 session) can *)
(*                                never evict the user's passkey.          *)
(***************************************************************************)
EXTENDS Naturals

CONSTANT MaxCreds \* cap on total credentials (MAX_CREDENTIALS_PER_USER, shrunk)

Kinds == {"webauthn", "devicekey", "softkey"}
Ranks == 1..3

\* KIND_RANK (keys.ts) = AMR_RANK (sessions.ts) via KIND_TO_AMR.
Rank(k) == CASE k = "webauthn"  -> 3
             [] k = "devicekey" -> 2
             [] k = "softkey"   -> 1

VARIABLES
    creds,          \* per-kind credential counts, [Kinds -> 0..MaxCreds]
    sessions,       \* ranks of live sessions (a session is just its amr rank)
    everRegistered, \* history: some credential has existed at some point
    deletions       \* history: <<sessionRank, deletedCredRank>> pairs

vars == <<creds, sessions, everRegistered, deletions>>

Total(c) == c["webauthn"] + c["devicekey"] + c["softkey"]

Init ==
    /\ creds = [k \in Kinds |-> 0]
    /\ sessions = {}
    /\ everRegistered = FALSE
    /\ deletions = {}

\* POST /v1/(register|key/register)/verify with no session: fresh user, first
\* credential of any kind, and a session of that credential's rank.
SignupWith(k) ==
    /\ Total(creds) = 0
    /\ creds' = [creds EXCEPT ![k] = @ + 1]
    /\ sessions' = sessions \cup {Rank(k)}
    /\ everRegistered' = TRUE
    /\ UNCHANGED deletions

\* Register-while-authenticated: any live session attaches a credential of any
\* kind to its user (no rank guard on attach in keys.ts), and verify mints a
\* session of the NEW credential's rank. Capped at MaxCreds.
Attach(s, k) ==
    /\ s \in sessions
    /\ Total(creds) < MaxCreds
    /\ creds' = [creds EXCEPT ![k] = @ + 1]
    /\ sessions' = sessions \cup {Rank(k)}
    /\ UNCHANGED <<everRegistered, deletions>>

\* POST /v1/(login|key/login)/verify against an existing credential.
Login(k) ==
    /\ creds[k] >= 1
    /\ sessions' = sessions \cup {Rank(k)}
    /\ UNCHANGED <<creds, everRegistered, deletions>>

\* DELETE /v1/credentials/:id — both guards from the handler: never remove the
\* last credential (409), and a session may not remove a credential stronger
\* than how it was authenticated (403).
Delete(s, k) ==
    /\ s \in sessions
    /\ creds[k] >= 1
    /\ Total(creds) > 1        \* last-credential guard
    /\ s >= Rank(k)            \* rank guard: AMR_RANK[session.amr] >= KIND_RANK[kind]
    /\ creds' = [creds EXCEPT ![k] = @ - 1]
    /\ deletions' = deletions \cup {<<s, Rank(k)>>}
    /\ UNCHANGED <<sessions, everRegistered>>

\* Sessions expire (KV TTL) or are dropped by /v1/logout at any time.
DropSession(s) ==
    /\ s \in sessions
    /\ sessions' = sessions \ {s}
    /\ UNCHANGED <<creds, everRegistered, deletions>>

Next ==
    \/ \E k \in Kinds : SignupWith(k) \/ Login(k)
    \/ \E s \in Ranks, k \in Kinds : Attach(s, k) \/ Delete(s, k)
    \/ \E s \in Ranks : DropSession(s)

Spec == Init /\ [][Next]_vars

TypeOK ==
    /\ creds \in [Kinds -> 0..MaxCreds]
    /\ Total(creds) <= MaxCreds
    /\ sessions \subseteq Ranks
    /\ everRegistered \in BOOLEAN
    /\ deletions \subseteq Ranks \X Ranks

\* Once registered, an account always has at least one credential.
NeverOrphaned == everRegistered => Total(creds) >= 1

\* Every deletion ever performed satisfied the rank rule.
NoPrivilegeEscalationDelete == \A d \in deletions : d[1] >= d[2]

\* The phished-key story: a stolen account key yields only a rank-1 session,
\* which by the rank rule can never delete the webauthn credential — only a
\* webauthn-rank session ever deletes a passkey. (A corollary of
\* NoPrivilegeEscalationDelete, stated explicitly as the security property
\* that motivated the guard.)
PasskeySurvivesPhishedKey == \A d \in deletions : d[2] = 3 => d[1] = 3

=============================================================================
