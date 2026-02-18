--------------------------- MODULE Gratos_Signup ---------------------------
EXTENDS Sequences, Naturals, TLC

CONSTANTS 
    Users,          \* Set of possible user identities
    Domains,        \* Set of possible domain names
    MaxTime         \* Time limit for expiration logic

VARIABLES
    userState,      \* Mapping of session -> [type: {"anon", "auth"}, user: Users \cup {Nil}]
    domainStatus,   \* Mapping of domain -> [status: {"available", "pending", "claimed"}, owner: Users \cup {Nil}, session: Sessions \cup {Nil}]
    cnameRecord,    \* Mapping of domain -> BOOLEAN (True if CNAME points to Gratos)
    currentTime     \* Global tick for expiration

Sessions == 1..3
Nil == "Nil"

vars == <<userState, domainStatus, cnameRecord, currentTime>>

TypeOK ==
    /\ userState \in [Sessions -> [type: {"anon", "auth"}, user: Users \cup {Nil}]]
    /\ domainStatus \in [Domains -> [status: {"available", "pending", "claimed"}, 
                                    owner: Users \cup {Nil}, 
                                    session: Sessions \cup {Nil},
                                    expiresAt: Naturals \cup {99}]]
    /\ cnameRecord \in [Domains -> BOOLEAN]
    /\ currentTime \in 0..MaxTime

Init ==
    /\ userState = [s \in Sessions |-> [type: "anon", user: Nil]]
    /\ domainStatus = [d \in Domains |-> [status: "available", owner: Nil, session: Nil, expiresAt: 99]]
    /\ cnameRecord = [d \in Domains |-> FALSE]
    /\ currentTime = 0

\* Actions

\* 1. User enters domain name (Anonymous session starts claim)
EnterDomain(s, d) ==
    /\ domainStatus[d].status = "available"
    /\ domainStatus' = [domainStatus EXCEPT ![d] = [status |-> "pending", 
                                                   owner |-> Nil, 
                                                   session |-> s,
                                                   expiresAt |-> currentTime + 2]]
    /\ UNCHANGED <<userState, cnameRecord, currentTime>>

\* 2. User authenticates (Login/Register with Passkey)
Authenticate(s, u) ==
    /\ userState[s].type = "anon"
    /\ userState' = [userState EXCEPT ![s] = [type |-> "auth", user |-> u]]
    /\ UNCHANGED <<domainStatus, cnameRecord, currentTime>>

\* 3. CNAME is updated in the real world (External event)
UpdateCNAME(d) ==
    /\ cnameRecord' = [cnameRecord EXCEPT ![d] = TRUE]
    /\ UNCHANGED <<userState, domainStatus, currentTime>>

\* 4. Claim Domain (Requires Auth + CNAME + Session match)
ClaimDomain(s, d) ==
    /\ domainStatus[d].session = s
    /\ userState[s].type = "auth"
    /\ cnameRecord[d] = TRUE
    /\ domainStatus' = [domainStatus EXCEPT ![d] = [status |-> "claimed", 
                                                   owner |-> userState[s].user, 
                                                   session |-> Nil,
                                                   expiresAt |-> 99]]
    /\ UNCHANGED <<userState, cnameRecord, currentTime>>

\* 5. Expiration logic
Expire(d) ==
    /\ domainStatus[d].status = "pending"
    /\ currentTime >= domainStatus[d].expiresAt
    /\ domainStatus' = [domainStatus EXCEPT ![d] = [status |-> "available", owner |-> Nil, session |-> Nil, expiresAt |-> 99]]
    /\ UNCHANGED <<userState, cnameRecord, currentTime>>

Tick ==
    /\ currentTime < MaxTime
    /\ currentTime' = currentTime + 1
    /\ UNCHANGED <<userState, domainStatus, cnameRecord>>

Next == 
    \/ \E s \in Sessions, d \in Domains : EnterDomain(s, d)
    \/ \E s \in Sessions, u \in Users : Authenticate(s, u)
    \/ \E d \in Domains : UpdateCNAME(d)
    \/ \E s \in Sessions, d \in Domains : ClaimDomain(s, d)
    \/ \E d \in Domains : Expire(d)
    \/ Tick

Spec == Init /\ [][Next]_vars

\* Invariants
OnlyOnePendingPerDomain == 
    \A d \in Domains : domainStatus[d].status = "pending" => domainStatus[d].session /= Nil

NoDoubleClaim ==
    \A d \in Domains : domainStatus[d].status = "claimed" => domainStatus[d].owner /= Nil

=============================================================================
