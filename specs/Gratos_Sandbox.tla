-------------------------- MODULE Gratos_Sandbox --------------------------
(***************************************************************************)
(* Sandbox lifecycle in gratos-multi after the ownership change.           *)
(*                                                                         *)
(* POST /sandbox mints a sandbox: anonymous when the request carries no    *)
(* session (user_id NULL), owned when it does. AuthRPC.sweepSandboxes      *)
(* deletes only aged anonymous sandboxes (user_id IS NULL filter); owned   *)
(* ones persist until their owner deletes them via DELETE /sandboxes/:sid. *)
(*                                                                         *)
(* Checked property: OwnedNeverSwept — no sandbox that was ever owned is   *)
(* removed by the sweep. This is what the SQL filter must guarantee.       *)
(***************************************************************************)
EXTENDS FiniteSets

CONSTANTS Ids

VARIABLES
    liveAnon,   \* anonymous sandboxes currently in the sandboxes table
    liveOwned,  \* owned sandboxes currently in the sandboxes table
    ownedEver,  \* ids that were ever minted as owned
    swept       \* ids removed by sweepSandboxes

vars == <<liveAnon, liveOwned, ownedEver, swept>>

Init ==
    /\ liveAnon = {}
    /\ liveOwned = {}
    /\ ownedEver = {}
    /\ swept = {}

\* Sandbox ids are random 12-hex-char strings — modeled as never reused.
Fresh(id) == id \notin (liveAnon \cup liveOwned \cup ownedEver \cup swept)

MintAnon(id) ==
    /\ Fresh(id)
    /\ liveAnon' = liveAnon \cup {id}
    /\ UNCHANGED <<liveOwned, ownedEver, swept>>

MintOwned(id) ==
    /\ Fresh(id)
    /\ liveOwned' = liveOwned \cup {id}
    /\ ownedEver' = ownedEver \cup {id}
    /\ UNCHANGED <<liveAnon, swept>>

\* sweepSandboxes: WHERE ... AND user_id IS NULL — anonymous rows only.
Sweep(id) ==
    /\ id \in liveAnon
    /\ liveAnon' = liveAnon \ {id}
    /\ swept' = swept \cup {id}
    /\ UNCHANGED <<liveOwned, ownedEver>>

\* DELETE /sandboxes/:sid — owner removes an owned sandbox.
Delete(id) ==
    /\ id \in liveOwned
    /\ liveOwned' = liveOwned \ {id}
    /\ UNCHANGED <<liveAnon, ownedEver, swept>>

Next ==
    \E id \in Ids :
        MintAnon(id) \/ MintOwned(id) \/ Sweep(id) \/ Delete(id)

Spec == Init /\ [][Next]_vars

TypeOK ==
    /\ liveAnon \subseteq Ids
    /\ liveOwned \subseteq Ids
    /\ ownedEver \subseteq Ids
    /\ swept \subseteq Ids

Disjoint == liveAnon \cap liveOwned = {}

OwnedNeverSwept == swept \cap ownedEver = {}

=============================================================================
