package gmail

# Make OPAL happy with Rego v1 Syntax
import future.keywords

# Rego v1 (OPA 1.x strict)

default allow := false

denied_recipients := {"yaoyaozong@gmail.com"}

# --- helpers ---

as_array(x) := [] if x == null
as_array(x) := x if type_name(x) == "array"
as_array(x) := [x] if type_name(x) == "string"

# --- recipients extraction (set) ---
# NOTE: In v1, partial set rules must use "contains" in the HEAD.

recipients contains addr if {
  a := object.get(input.tool, "arguments", {})
  addr := as_array(object.get(a, "to", null))[_]
}

recipients contains addr if {
  a := object.get(input.tool, "arguments", {})
  addr := as_array(object.get(a, "cc", null))[_]
}

recipients contains addr if {
  a := object.get(input.tool, "arguments", {})
  addr := as_array(object.get(a, "bcc", null))[_]
}

recipients contains addr if {
  a := object.get(input.tool, "arguments", {})
  m := object.get(a, "message", {})
  addr := as_array(object.get(m, "to", null))[_]
}

# --- deny reasons (set) ---

deny contains reason if {
  recipients[recipient]                 # membership test (NO "contains" here)
  denied_recipients[blocked]            # membership test
  lower(recipient) == lower(blocked)
  reason := sprintf("recipient %s is blocked", [blocked])
}

# --- allow / reason / decision ---

allow if {
  count(deny) == 0
}

reason := "ok" if {
  allow
}

reason := r if {
  not allow
  deny[r]
}

decision := {
  "allow": allow,
  "reason": reason,
}
