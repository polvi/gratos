--------------------------- MODULE Gratos_Authz ----------------------------
(***************************************************************************)
(* Bootstrap/admin-tuple lifecycle in the gratos-authz worker (single      *)
(* tenant; permission-graph evaluation is out of scope).                   *)
(*                                                                         *)
(* Admin state is the set of gratos_authz:root#admin@user:<id> tuples.     *)
(* POST /v1/authz/bootstrap lets any user with a valid tenant session try  *)
(* to become the first admin. The handler is a single conditional INSERT   *)
(* (INSERT ... SELECT ... WHERE NOT EXISTS any admin tuple), so the        *)
(* empty-check and the insert are atomic in D1; meta.changes == 0 is the   *)
(* 409 path. We model it two-phase — StartBootstrap observes admins = {},  *)
(* CommitBootstrap re-checks admins = {} atomically — to expose the        *)
(* check-then-insert race the conditional INSERT closes: dropping the      *)
(* re-check (a naive read-then-INSERT) lets two concurrent callers both    *)
(* win, violating BootstrapUnique.                                         *)
(*                                                                         *)
(* Admins grant/revoke admin tuples via the normal tuple API and perform   *)
(* other schema/tuple writes (Mutate), all gated on membership in admins   *)
(* at the time of the write. Revoking the last admin empties the set and   *)
(* deliberately REOPENS bootstrap — that is a design decision, not a bug,  *)
(* and the spec exercises reachable states with admins = {}.               *)
(*                                                                         *)
(* Checked properties:                                                     *)
(*   TypeOK                                                                *)
(*   BootstrapUnique    — at most one user ever holds admin without having *)
(*                        been granted it: concurrent bootstrap attempts   *)
(*                        cannot produce two winners at once.              *)
(*   MutatorsWereAdmins — every user that performed a gated write was an   *)
(*                        admin at some point.                             *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets

CONSTANTS Users

VARIABLES
    admins,     \* users currently holding a root#admin tuple
    inflight,   \* bootstrap callers that observed admins = {} (pre-INSERT)
    everAdmins, \* history: users that ever held admin
    granted,    \* history: users that ever received admin via Grant
    mutators    \* history: users that ever performed a gated Mutate

vars == <<admins, inflight, everAdmins, granted, mutators>>

Init ==
    /\ admins = {}
    /\ inflight = {}
    /\ everAdmins = {}
    /\ granted = {}
    /\ mutators = {}

\* Bootstrap phase 1: handler is entered while no admin tuple exists.
StartBootstrap(u) ==
    /\ admins = {}
    /\ u \notin inflight
    /\ inflight' = inflight \cup {u}
    /\ UNCHANGED <<admins, everAdmins, granted, mutators>>

\* Bootstrap phase 2, success: the conditional INSERT's WHERE NOT EXISTS
\* re-check passes atomically with the insert (meta.changes == 1).
CommitBootstrap(u) ==
    /\ u \in inflight
    /\ admins = {}
    /\ admins' = admins \cup {u}
    /\ everAdmins' = everAdmins \cup {u}
    /\ inflight' = inflight \ {u}
    /\ UNCHANGED <<granted, mutators>>

\* Bootstrap phase 2, failure: an admin tuple appeared since the observation,
\* meta.changes == 0, handler returns 409.
AbortBootstrap(u) ==
    /\ u \in inflight
    /\ admins # {}
    /\ inflight' = inflight \ {u}
    /\ UNCHANGED <<admins, everAdmins, granted, mutators>>

\* An admin writes root#admin@user:u via the normal tuple API.
Grant(a, u) ==
    /\ a \in admins
    /\ u \notin admins
    /\ admins' = admins \cup {u}
    /\ everAdmins' = everAdmins \cup {u}
    /\ granted' = granted \cup {u}
    /\ UNCHANGED <<inflight, mutators>>

\* An admin deletes an admin tuple (self-revoke allowed). Deleting the last
\* admin empties the set and reopens bootstrap — intentional.
Revoke(a, u) ==
    /\ a \in admins
    /\ u \in admins
    /\ admins' = admins \ {u}
    /\ UNCHANGED <<inflight, everAdmins, granted, mutators>>

\* Any other schema/tuple write, gated on admin membership at write time.
Mutate(a) ==
    /\ a \in admins
    /\ a \notin mutators
    /\ mutators' = mutators \cup {a}
    /\ UNCHANGED <<admins, inflight, everAdmins, granted>>

Next ==
    \/ \E u \in Users : StartBootstrap(u) \/ CommitBootstrap(u)
                        \/ AbortBootstrap(u) \/ Mutate(u)
    \/ \E a \in Users, u \in Users : Grant(a, u) \/ Revoke(a, u)

Spec == Init /\ [][Next]_vars

TypeOK ==
    /\ admins \subseteq Users
    /\ inflight \subseteq Users
    /\ everAdmins \subseteq Users
    /\ granted \subseteq everAdmins
    /\ mutators \subseteq Users
    /\ admins \subseteq everAdmins

\* Concurrent bootstrap cannot yield two winners: at most one current admin
\* holds the role without having been granted it.
BootstrapUnique == Cardinality(admins \ granted) <= 1

\* Gated writes only ever came from (sometime-)admins.
MutatorsWereAdmins == mutators \subseteq everAdmins

=============================================================================
