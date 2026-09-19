---------------------------- MODULE Gratos_Code ----------------------------
(***************************************************************************)
(* App-delivered sign-in codes for admin-provisioned accounts              *)
(* (gratos-multi; amr "otp" in src/sessions.ts).                           *)
(*                                                                         *)
(* Accounts are created only by the tenant's trusted app backend (service  *)
(* token). A browser starts a sign-in ticket and receives the ticket id    *)
(* plus a secret verifier that only that browser holds. The app backend    *)
(* then mints a short code for (ticket, user) and delivers it out of band  *)
(* (SMS, voice, email). The browser redeems it with verify(ticket,         *)
(* verifier, code), which yields a session with amr "otp" (rank 0).        *)
(*                                                                         *)
(* Actors:                                                                 *)
(*   app backend — CreateUser, DeleteUser, MintCode (trusted, but it will  *)
(*                 mint for any live user on any open ticket; that is the  *)
(*                 worst case the server must tolerate).                   *)
(*   browsers    — Start, Verify, AddCred, Login. One browser is the       *)
(*                 Attacker: it can start its own tickets and knows only   *)
(*                 the verifiers of tickets it started. Its Verify may     *)
(*                 present ANY code value, which subsumes both guessing    *)
(*                 and codes learned from a leaked delivery (overheard,    *)
(*                 voicemail); the code alphabet is tiny on purpose.       *)
(*   environment — Expire (ticket deadline passes at any moment).          *)
(*                                                                         *)
(* Ticket lifecycle: unused -> open -> (claimed -> gone) | gone.           *)
(*   MintCode: open ticket, mints < MaxMints, live user, and the ticket is *)
(*             not already bound to a different user (codes.ts answers 400 *)
(*             "Ticket belongs to another user"). A re-mint replaces the   *)
(*             code and resets tries. The per-user hourly mint limit       *)
(*             (USER_MINTS_PER_HOUR) is not modeled.                       *)
(*   Verify:   the verifier must be this ticket's (BindVerifier). A wrong  *)
(*             verifier is rejected with no state change (it neither burns *)
(*             a try nor reveals anything). A wrong code increments tries; *)
(*             reaching MaxTries deletes the ticket. The right code        *)
(*             DELETES THE TICKET FIRST (state "claimed": gone from the    *)
(*             store, so no second verify can match it) and only then      *)
(*             FinishVerify mints the otp session. With VerifyChecksUser   *)
(*             the mint re-checks that the user still exists. The try and  *)
(*             the claim are atomic takes; the implementation makes that   *)
(*             true with D1 conditional UPDATE/DELETE ... RETURNING        *)
(*             (code_tickets, migration 0009), not KV get-then-put.        *)
(*                                                                         *)
(* Session ranks: otp=0 < key=1 < device=2 < webauthn=3. AddCred (register *)
(* while authenticated) re-mints the session at                            *)
(* min(existing amr, new credential's rank) when CapAddAmr (weakerAmr in   *)
(* sessions.ts); Login with a credential mints at that credential's rank.  *)
(*                                                                         *)
(* Every session carries two bookkeeping ranks (not part of the real       *)
(* session value, used only to state properties):                          *)
(*   floor — the weakest authenticator in its re-mint chain               *)
(*           (otp -> add -> add ...); a fresh Login starts a new chain.    *)
(*   root  — the weakest link in its full provenance, including how the    *)
(*           credential used to Login was itself enrolled.                 *)
(*                                                                         *)
(* Checked invariants (Gratos_Code.cfg):                                   *)
(*   TypeOK                                                                *)
(*   OneSessionPerTicket  — each ticket/code yields at most one session.   *)
(*   OtpBoundToStarter    — every otp session came from a verify that      *)
(*                          presented the verifier of the browser that     *)
(*                          started the ticket: a leaked code never lets   *)
(*                          the attacker redeem someone else's ticket.     *)
(*   TriesBounded         — tries never exceeds MaxTries (an open ticket   *)
(*                          always has tries < MaxTries).                  *)
(*   MintsBounded         — mints never exceeds MaxMints.                  *)
(*   GuessBudget          — total wrong codes against one ticket, across   *)
(*                          re-mints, is at most MaxMints * MaxTries.      *)
(*   SessionsForLiveUsers — sessions exist only for existing users.        *)
(*   CodesForLiveUsers    — a code is only ever bound to a user the app    *)
(*                          backend created.                               *)
(*   AddNeverExceedsParent — a session minted by credential-add never      *)
(*                          outranks the session that performed the add.   *)
(*   ChainBound           — no session outranks the weakest authenticator  *)
(*                          in its re-mint chain.                          *)
(*                                                                         *)
(* Documented NON-invariants (true of the design; see the report / run     *)
(* with an alternate cfg to get the trace):                                *)
(*   ProvenanceBound, LeakedCodeYieldsOnlyOtp — an otp session can enroll *)
(*   a passkey, and a later Login with that passkey is webauthn rank. The  *)
(*   add cap bounds the chain, not the credential it creates.             *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets

CONSTANTS
    Browsers,         \* browser instances, including the attacker
    Attacker,         \* the attacker's browser (\in Browsers)
    Users,            \* user ids the app backend may create
    Tickets,          \* ticket ids; each is used at most once (random ids)
    Codes,            \* code alphabet (shrunk)
    Kinds,            \* credential kinds modeled (subset of the three below)
    MaxMints,         \* code mints per ticket (3 in the design, shrunk)
    MaxTries,         \* wrong codes per mint before the ticket dies (5, shrunk)
    MaxCreds,         \* credentials per user (MAX_CREDENTIALS_PER_USER, shrunk)
    BindVerifier,     \* TRUE = verify checks the ticket's verifier
    VerifyChecksUser, \* TRUE = the session mint re-checks the user exists
    CapAddAmr         \* TRUE = credential-add re-mints at min(amr, new rank)

ASSUME Attacker \in Browsers
ASSUME MaxMints \in Nat /\ MaxMints >= 1
ASSUME MaxTries \in Nat /\ MaxTries >= 1
ASSUME Kinds \subseteq {"webauthn", "devicekey", "softkey"}

NoB == "noBrowser"
NoU == "noUser"
NoC == "noCode"

Ranks == 0..3
OTP == 0

\* AMR_RANK (sessions.ts) via KIND_TO_AMR.
Rank(k) == CASE k = "webauthn"  -> 3
             [] k = "devicekey" -> 2
             [] k = "softkey"   -> 1

Min(a, b) == IF a <= b THEN a ELSE b

\* The verifiers a browser can present: those of the tickets it started.
Verifiers(b, own) == {t \in Tickets : own[t] = b}

Session == [u : Users, amr : Ranks, floor : Ranks, root : Ranks, b : Browsers]
Cred    == [u : Users, k : Kinds, b : Browsers, root : Ranks]

VARIABLES
    ustate,    \* [Users -> {"none","live","deleted"}]; ids are UUIDs, never reused
    tstate,    \* [Tickets -> {"unused","open","claimed","gone"}]
    owner,     \* [Tickets -> Browsers \cup {NoB}] browser that started it (kept after deletion)
    tuser,     \* [Tickets -> Users \cup {NoU}]   user of the current code
    tcode,     \* [Tickets -> Codes \cup {NoC}]   current code
    mints,     \* [Tickets -> 0..MaxMints]
    tries,     \* [Tickets -> 0..MaxTries]         wrong codes since last mint
    guesses,   \* [Tickets -> Nat]                 history: wrong codes ever
    claimedBy, \* [Tickets -> Browsers \cup {NoB}] browser whose verify claimed it
    sessions,  \* set of Session
    creds,     \* set of Cred
    otpCount,  \* [Tickets -> Nat]                 history: otp sessions minted per ticket
    otpLog,    \* history: <<ticket, presenting browser>> of every otp session
    addLog     \* history: <<parent amr, new amr>> of every credential-add re-mint

vars == <<ustate, tstate, owner, tuser, tcode, mints, tries, guesses,
          claimedBy, sessions, creds, otpCount, otpLog, addLog>>

ticketVars == <<tstate, owner, tuser, tcode, mints, tries, guesses, claimedBy>>
histVars   == <<otpCount, otpLog, addLog>>

Init ==
    /\ ustate = [u \in Users |-> "none"]
    /\ tstate = [t \in Tickets |-> "unused"]
    /\ owner = [t \in Tickets |-> NoB]
    /\ tuser = [t \in Tickets |-> NoU]
    /\ tcode = [t \in Tickets |-> NoC]
    /\ mints = [t \in Tickets |-> 0]
    /\ tries = [t \in Tickets |-> 0]
    /\ guesses = [t \in Tickets |-> 0]
    /\ claimedBy = [t \in Tickets |-> NoB]
    /\ sessions = {}
    /\ creds = {}
    /\ otpCount = [t \in Tickets |-> 0]
    /\ otpLog = {}
    /\ addLog = {}

-----------------------------------------------------------------------------
(* App backend (service token).                                            *)

CreateUser(u) ==
    /\ ustate[u] = "none"
    /\ ustate' = [ustate EXCEPT ![u] = "live"]
    /\ UNCHANGED <<ticketVars, sessions, creds, histVars>>

\* Deleting a user revokes its sessions and credentials. Open tickets that
\* carry a code for it are NOT touched here (the ticket store is keyed by
\* ticket, not user); the verify-time re-check covers them.
DeleteUser(u) ==
    /\ ustate[u] = "live"
    /\ ustate' = [ustate EXCEPT ![u] = "deleted"]
    /\ sessions' = {s \in sessions : s.u # u}
    /\ creds' = {c \in creds : c.u # u}
    /\ UNCHANGED <<ticketVars, histVars>>

\* Mint (or re-mint) a code on an open ticket for a live user. A re-mint
\* replaces the code and resets tries; the first mint binds the ticket's user.
MintCode(t, u, c) ==
    /\ tstate[t] = "open"
    /\ mints[t] < MaxMints
    /\ ustate[u] = "live"
    /\ tuser[t] \in {NoU, u}
    /\ tuser' = [tuser EXCEPT ![t] = u]
    /\ tcode' = [tcode EXCEPT ![t] = c]
    /\ mints' = [mints EXCEPT ![t] = @ + 1]
    /\ tries' = [tries EXCEPT ![t] = 0]
    /\ UNCHANGED <<ustate, tstate, owner, guesses, claimedBy, sessions, creds,
                   histVars>>

-----------------------------------------------------------------------------
(* Browsers.                                                               *)

\* start: a fresh ticket; the response's verifier is known only to b.
Start(b, t) ==
    /\ tstate[t] = "unused"
    /\ tstate' = [tstate EXCEPT ![t] = "open"]
    /\ owner' = [owner EXCEPT ![t] = b]
    /\ UNCHANGED <<ustate, tuser, tcode, mints, tries, guesses, claimedBy,
                   sessions, creds, histVars>>

\* verify(ticket t, verifier v, code c) from browser b. v ranges over the
\* verifiers b actually holds. A mismatched verifier, or a ticket with no
\* code yet, is a rejected no-op (not modeled as a step).
Verify(b, t, v, c) ==
    /\ tstate[t] = "open"
    /\ v \in Verifiers(b, owner)
    /\ BindVerifier => v = t
    /\ tcode[t] # NoC
    /\ IF c = tcode[t]
         THEN \* right code: take the ticket out of the store first
              /\ tstate' = [tstate EXCEPT ![t] = "claimed"]
              /\ claimedBy' = [claimedBy EXCEPT ![t] = b]
              /\ UNCHANGED <<tries, guesses>>
         ELSE \* wrong code: burn a try; the last one kills the ticket
              /\ tries' = [tries EXCEPT ![t] = @ + 1]
              /\ guesses' = [guesses EXCEPT ![t] = @ + 1]
              /\ tstate' = [tstate EXCEPT ![t] =
                              IF tries[t] + 1 >= MaxTries THEN "gone" ELSE @]
              /\ UNCHANGED claimedBy
    /\ UNCHANGED <<ustate, owner, tuser, tcode, mints, sessions, creds,
                   histVars>>

\* Second half of a successful verify: the ticket is already gone; mint the
\* otp session for the ticket's user (if it still exists).
FinishVerify(t) ==
    /\ tstate[t] = "claimed"
    /\ tstate' = [tstate EXCEPT ![t] = "gone"]
    /\ LET u == tuser[t]
           b == claimedBy[t]
       IN IF VerifyChecksUser => ustate[u] = "live"
            THEN /\ sessions' = sessions \cup
                      {[u |-> u, amr |-> OTP, floor |-> OTP, root |-> OTP, b |-> b]}
                 /\ otpCount' = [otpCount EXCEPT ![t] = @ + 1]
                 /\ otpLog' = otpLog \cup {<<t, b>>}
            ELSE UNCHANGED <<sessions, otpCount, otpLog>>
    /\ UNCHANGED <<ustate, owner, tuser, tcode, mints, tries, guesses,
                   claimedBy, creds, addLog>>

\* Register while authenticated: the session's holder enrolls a credential
\* of kind k for the session's user, and verify re-mints the session.
AddCred(s, k) ==
    /\ s \in sessions
    /\ ustate[s.u] = "live"
    /\ Cardinality({c \in creds : c.u = s.u}) < MaxCreds
    /\ LET newAmr == IF CapAddAmr THEN Min(s.amr, Rank(k)) ELSE Rank(k)
           root   == Min(s.root, Rank(k))
           cr     == [u |-> s.u, k |-> k, b |-> s.b, root |-> root]
       IN /\ cr \notin creds          \* re-enrolling the same authenticator: 409
          /\ creds' = creds \cup {cr}
          /\ sessions' = sessions \cup
               {[u |-> s.u, amr |-> newAmr, floor |-> Min(s.floor, Rank(k)),
                 root |-> root, b |-> s.b]}
          /\ addLog' = addLog \cup {<<s.amr, newAmr>>}
    /\ UNCHANGED <<ustate, ticketVars, otpCount, otpLog>>

\* Login with a credential the browser holds: a new chain at its rank.
Login(cr) ==
    /\ cr \in creds
    /\ ustate[cr.u] = "live"
    /\ sessions' = sessions \cup
         {[u |-> cr.u, amr |-> Rank(cr.k), floor |-> Rank(cr.k),
           root |-> cr.root, b |-> cr.b]}
    /\ UNCHANGED <<ustate, ticketVars, creds, histVars>>

-----------------------------------------------------------------------------
(* Environment.                                                            *)

\* Deadline: an open ticket can expire at any moment.
Expire(t) ==
    /\ tstate[t] = "open"
    /\ tstate' = [tstate EXCEPT ![t] = "gone"]
    /\ UNCHANGED <<ustate, owner, tuser, tcode, mints, tries, guesses,
                   claimedBy, sessions, creds, histVars>>

Next ==
    \/ \E u \in Users : CreateUser(u) \/ DeleteUser(u)
    \/ \E t \in Tickets, u \in Users, c \in Codes : MintCode(t, u, c)
    \/ \E b \in Browsers, t \in Tickets : Start(b, t)
    \/ \E b \in Browsers, t, v \in Tickets, c \in Codes : Verify(b, t, v, c)
    \/ \E t \in Tickets : FinishVerify(t) \/ Expire(t)
    \/ \E s \in sessions, k \in Kinds : AddCred(s, k)
    \/ \E cr \in creds : Login(cr)

Spec == Init /\ [][Next]_vars

-----------------------------------------------------------------------------
(* Properties.                                                             *)

TypeOK ==
    /\ ustate \in [Users -> {"none", "live", "deleted"}]
    /\ tstate \in [Tickets -> {"unused", "open", "claimed", "gone"}]
    /\ owner \in [Tickets -> Browsers \cup {NoB}]
    /\ tuser \in [Tickets -> Users \cup {NoU}]
    /\ tcode \in [Tickets -> Codes \cup {NoC}]
    /\ mints \in [Tickets -> 0..MaxMints]
    /\ tries \in [Tickets -> 0..MaxTries]
    /\ guesses \in [Tickets -> Nat]
    /\ claimedBy \in [Tickets -> Browsers \cup {NoB}]
    /\ sessions \subseteq Session
    /\ creds \subseteq Cred
    /\ otpCount \in [Tickets -> Nat]
    /\ otpLog \subseteq Tickets \X Browsers
    /\ addLog \subseteq Ranks \X Ranks

\* Each ticket (hence each delivered code) yields at most one session.
OneSessionPerTicket == \A t \in Tickets : otpCount[t] <= 1

\* Every otp session was redeemed by the browser that started its ticket,
\* i.e. with that browser's verifier. In particular the attacker never
\* gets a session from a ticket another browser started, leaked code or not.
OtpBoundToStarter == \A p \in otpLog : p[2] = owner[p[1]]

\* Stated directly for the attacker.
AttackerOnlyRedeemsOwnTickets ==
    \A p \in otpLog : p[2] = Attacker => owner[p[1]] = Attacker

TriesBounded ==
    \A t \in Tickets :
        /\ tries[t] <= MaxTries
        /\ tstate[t] = "open" => tries[t] < MaxTries

MintsBounded == \A t \in Tickets : mints[t] <= MaxMints

\* Re-mints reset tries, so the true guessing budget per ticket is
\* MaxMints * MaxTries; a code is only minted by the app backend.
GuessBudget == \A t \in Tickets : guesses[t] <= MaxMints * MaxTries

SessionsForLiveUsers == \A s \in sessions : ustate[s.u] = "live"

CodesForLiveUsers ==
    \A t \in Tickets : tuser[t] # NoU => ustate[tuser[t]] # "none"

\* A code for a ticket exists only once the ticket was started.
NoCodeBeforeStart ==
    \A t \in Tickets : tcode[t] # NoC => owner[t] # NoB

AddNeverExceedsParent == \A p \in addLog : p[2] <= p[1]

ChainBound == \A s \in sessions : s.amr <= s.floor

\* --- Expected to FAIL under the current design (not in Gratos_Code.cfg). ---

\* No session outranks the weakest link in its full provenance.
ProvenanceBound == \A s \in sessions : s.amr <= s.root

\* An attacker who only ever had codes holds nothing above otp rank.
LeakedCodeYieldsOnlyOtp == \A s \in sessions : s.b = Attacker => s.amr = OTP

=============================================================================
