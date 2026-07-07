#! VULNERABLE bed-assignment — feeds the untrusted input straight to the tool, no extraction.
#! check -> UNSAFE: tainted data cannot reach a capability.
grant assignBed

let raw = fetch<web>
privileged { assignBed(raw) }  # tainted -> tool: REJECTED
