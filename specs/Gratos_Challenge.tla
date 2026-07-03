------------------------- MODULE Gratos_Challenge -------------------------
(***************************************************************************)
(* Models the challenge-keyed pending-ceremony state in gratos-multi.     *)
(*                                                                         *)
(* KV keys are {reg,auth}_challenge:{tenant}:{challenge}: Issue writes a   *)
(* key (options endpoint), Verify consumes it (get + delete before         *)
(* verification), Expire models the 300s TTL. There is no separate         *)
(* correlation id — the challenge itself, recovered from the signed        *)
(* clientDataJSON, is the key.                                             *)
(*                                                                         *)
(* Checked properties:                                                     *)
(*   - NoReplay: a consumed (tenant, challenge) pair never re-enters       *)
(*     pending, so a credential response can verify at most once.          *)
(*   - Cross-tenant isolation is structural: Verify(t, ch) requires the    *)
(*     pair for that tenant in pending; a challenge issued for another     *)
(*     tenant can never be consumed under t (tenant-namespaced key).       *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets

CONSTANTS Tenants, Challenges

VARIABLES
    pending,   \* set of <<tenant, challenge>> currently live in KV
    consumed   \* set of <<tenant, challenge>> that have been verified

vars == <<pending, consumed>>

Pairs == Tenants \X Challenges

Init ==
    /\ pending = {}
    /\ consumed = {}

\* Options endpoint: mint a fresh challenge for a tenant. Challenges are
\* 32 random bytes from @simplewebauthn/server, so a value never repeats —
\* encoded here by excluding both live and already-consumed pairs.
Issue(t, ch) ==
    /\ <<t, ch>> \notin pending
    /\ <<t, ch>> \notin consumed
    /\ pending' = pending \cup {<<t, ch>>}
    /\ UNCHANGED consumed

\* Verify endpoint: get + delete the KV key, atomically consuming the
\* challenge before the WebAuthn verification runs.
Verify(t, ch) ==
    /\ <<t, ch>> \in pending
    /\ pending' = pending \ {<<t, ch>>}
    /\ consumed' = consumed \cup {<<t, ch>>}

\* KV TTL: a pending challenge silently disappears after 300s.
Expire(t, ch) ==
    /\ <<t, ch>> \in pending
    /\ pending' = pending \ {<<t, ch>>}
    /\ UNCHANGED consumed

Next ==
    \E t \in Tenants, ch \in Challenges :
        Issue(t, ch) \/ Verify(t, ch) \/ Expire(t, ch)

Spec == Init /\ [][Next]_vars

TypeOK ==
    /\ pending \subseteq Pairs
    /\ consumed \subseteq Pairs

\* Single-use: once verified, a pair can never be live again, so a second
\* POST of the same credential response always fails the KV lookup.
NoReplay == pending \cap consumed = {}

=============================================================================
