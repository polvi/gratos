------------------------ MODULE Gratos_Credentials -------------------------
(***************************************************************************)
(* Credential lifecycle of one account (gratos-multi src/auth.ts +         *)
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
(*                    credentials are capped at MAX_CREDENTIALS_PER_USER;  *)
(*                    both the passkey path (auth.ts) and the key path     *)
(*                    (keys.ts) enforce the cap, so it holds for every     *)
(*                    kind (MaxCreds is the cap, shrunk to bound state).   *)
(*   AttachDuplicate(s) — a live session re-presents a credential that is  *)
(*                    already registered: register options carry           *)
(*                    excludeCredentials and verify checks                 *)
(*                    getCredentialById, answering 409. Nothing changes:   *)
(*                    no new credential, no new session, no deletion. Only *)
(*                    the history flag everDuplicated records the attempt  *)
(*                    (so TLC does not fold it into stuttering).           *)
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
(*   DuplicateAddsNothing       — a duplicate attach is only ever observed *)
(*                                while a credential exists (it never      *)
(*                                creates one and never removes one).      *)
(***************************************************************************)
EXTENDS Naturals

CONSTANT MaxCreds \* cap on total credentials (MAX_CREDENTIALS_PER_USER, shrunk;
                  \* enforced by both the passkey and the key attach paths)

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
    everDuplicated, \* history: a duplicate attach (409) has been attempted
    deletions       \* history: <<sessionRank, deletedCredRank>> pairs

vars == <<creds, sessions, everRegistered, everDuplicated, deletions>>

Total(c) == c["webauthn"] + c["devicekey"] + c["softkey"]

Init ==
    /\ creds = [k \in Kinds |-> 0]
    /\ sessions = {}
    /\ everRegistered = FALSE
    /\ everDuplicated = FALSE
    /\ deletions = {}

\* POST /v1/(register|key/register)/verify with no session: fresh user, first
\* credential of any kind, and a session of that credential's rank.
SignupWith(k) ==
    /\ Total(creds) = 0
    /\ creds' = [creds EXCEPT ![k] = @ + 1]
    /\ sessions' = sessions \cup {Rank(k)}
    /\ everRegistered' = TRUE
    /\ UNCHANGED <<everDuplicated, deletions>>

\* Register-while-authenticated: any live session attaches a credential of any
\* kind to its user (no rank guard on attach in auth.ts or keys.ts), and verify
\* mints a session of the NEW credential's rank. Capped at MaxCreds on both the
\* passkey path (auth.ts) and the key path (keys.ts).
Attach(s, k) ==
    /\ s \in sessions
    /\ Total(creds) < MaxCreds
    /\ creds' = [creds EXCEPT ![k] = @ + 1]
    /\ sessions' = sessions \cup {Rank(k)}
    /\ UNCHANGED <<everRegistered, everDuplicated, deletions>>

\* Register-while-authenticated with a credential that is already registered:
\* register/options lists it in excludeCredentials and register/verify checks
\* getCredentialById, answering 409 "Credential already registered". The
\* account is untouched (no credential, no session, no deletion); only the
\* history flag records that the attempt happened.
AttachDuplicate(s) ==
    /\ s \in sessions
    /\ Total(creds) >= 1
    /\ everDuplicated' = TRUE
    /\ UNCHANGED <<creds, sessions, everRegistered, deletions>>

\* POST /v1/(login|key/login)/verify against an existing credential.
Login(k) ==
    /\ creds[k] >= 1
    /\ sessions' = sessions \cup {Rank(k)}
    /\ UNCHANGED <<creds, everRegistered, everDuplicated, deletions>>

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
    /\ UNCHANGED <<sessions, everRegistered, everDuplicated>>

\* Sessions expire (KV TTL) or are dropped by /v1/logout at any time.
DropSession(s) ==
    /\ s \in sessions
    /\ sessions' = sessions \ {s}
    /\ UNCHANGED <<creds, everRegistered, everDuplicated, deletions>>

Next ==
    \/ \E k \in Kinds : SignupWith(k) \/ Login(k)
    \/ \E s \in Ranks, k \in Kinds : Attach(s, k) \/ Delete(s, k)
    \/ \E s \in Ranks : AttachDuplicate(s) \/ DropSession(s)

Spec == Init /\ [][Next]_vars

TypeOK ==
    /\ creds \in [Kinds -> 0..MaxCreds]
    /\ Total(creds) <= MaxCreds
    /\ sessions \subseteq Ranks
    /\ everRegistered \in BOOLEAN
    /\ everDuplicated \in BOOLEAN
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

\* A duplicate attach (409) adds nothing and removes nothing: whenever one has
\* been observed, the account still holds at least one credential.
DuplicateAddsNothing == everDuplicated => Total(creds) >= 1

=============================================================================
