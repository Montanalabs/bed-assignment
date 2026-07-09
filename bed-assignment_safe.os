#! Bed-assignment agent — untrusted a request can only ever become one of a fixed set of decisions over a
#! closed type, never a tool argument. An injected instruction cannot be represented in the
#! closed type, so it is rejected at the trust boundary (and re-clamped at run time by extract).
#! @requires assignBed — the bed-assignment agent sink
#! @effect io
#! @taint bridge — extract<Decision> turns the tainted input into a trusted decision
grant assignBed

type Ward = Icu | GeneralW | Pediatric
type Decision = AssignBed(Ward) | Waitlist

let raw = fetch<web>  # UNTRUSTED a request — tainted
quarantined { let d = extract<Decision>(raw) }  # only a fixed Decision (payloads too) crosses
privileged { assignBed(d) }  # act on the trusted decision only
