------------------------------- MODULE CITraceR22 -------------------------------
EXTENDS Naturals, TLC
VARIABLES phase, revoked, ref, ack, now, pushes
vars == <<phase, revoked, ref, ack, now, pushes>>
Init == /\ phase = "Issued"
        /\ revoked = FALSE
        /\ ref = "Absent"
        /\ ack = FALSE
        /\ now = 0
        /\ pushes = 0
Revocation == /\ phase = "Issued"
              /\ ~revoked
              /\ revoked' = TRUE
              /\ phase' = "Revoked"
              /\ UNCHANGED <<ref, ack, now, pushes>>
Reserve == /\ phase = "Issued"
           /\ ~revoked
           /\ now < 2
           /\ phase' = "Reserved"
           /\ UNCHANGED <<revoked, ref, ack, now, pushes>>
Publish == /\ phase = "Reserved"
           /\ ref = "Absent"
           /\ ref' = "Candidate"
           /\ pushes' = pushes + 1
           /\ phase' = "AwaitACK"
           /\ UNCHANGED <<revoked, ack, now>>
VerifiedACK == /\ phase = "AwaitACK"
               /\ ref = "Candidate"
               /\ ack' = TRUE
               /\ phase' = "Published"
               /\ UNCHANGED <<revoked, ref, now, pushes>>
Crash == /\ phase = "AwaitACK"
         /\ ref = "Candidate"
         /\ phase' = "Crashed"
         /\ UNCHANGED <<revoked, ref, ack, now, pushes>>
Recover == /\ phase = "Crashed"
           /\ ref = "Candidate"
           /\ phase' = "Published"
           /\ ack' = TRUE
           /\ UNCHANGED <<revoked, ref, now, pushes>>
CompetingCreate == /\ ref = "Absent"
                   /\ ref' = "Other"
                   /\ UNCHANGED <<phase, revoked, ack, now, pushes>>
Tick == /\ now < 3
        /\ now' = now + 1
        /\ UNCHANGED <<phase, revoked, ref, ack, pushes>>
Next == Revocation \/ Reserve \/ Publish \/ VerifiedACK \/ Crash \/ Recover \/ CompetingCreate \/ Tick
Spec == Init /\ [][Next]_vars
TypeOK == /\ phase \in {"Issued","Reserved","Revoked","AwaitACK","Crashed","Published"}
          /\ revoked \in BOOLEAN
          /\ ref \in {"Absent","Other","Candidate"}
          /\ ack \in BOOLEAN
          /\ now \in 0..3
          /\ pushes \in Nat
AtMostOnePush == pushes <= 1
AckHasProof == ack => /\ ref = "Candidate" /\ pushes = 1
NoPushAfterEarlyRevocation == revoked => pushes = 0
PublishedHasACK == phase = "Published" => ack
================================================================================