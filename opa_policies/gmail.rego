package gmail

import future.keywords

# --- Config resolver (local vs OPAL namespaced bundle) ---

cfg := c if {
  c := data.config
}

cfg := c if {
  not data.config
  c := data["opa_policies"].config
}


default allow = false

default decision = {
  "allow": false,
  "decision": "DENY",
  "reason": "missing_decision",
  "reasons": ["missing_decision"],
  "risk": "high"
}

# -------------------------
# Helpers
# -------------------------

trim_ws(s) = out if {
  out := trim(sprintf("%v", [s]), " \t\r\n")
}

tool := object.get(input, "tool", {})
request := object.get(input, "request", {})
request_body := object.get(request, "body", {})
request_headers := object.get(request, "headers", {})

raw_tool_name := object.get(tool, "name", object.get(request_body, "name", ""))
tool_name := lower(trim_ws(raw_tool_name))

tool_args := object.get(tool, "arguments", object.get(request_body, "arguments", {}))

requester_identity := lower(trim_ws(
  object.get(
    object.get(input, "requester", {}),
    "identity",
    object.get(request_headers, "x-authenticated-user", "")
  )
))

# -------------------------
# Role-based access control
# -------------------------

user_has_role(user_id, role_name) if {
  roles_array := object.get(cfg.user_roles, "roles", [])
  role := roles_array[_]
  role.name == role_name
  role.members[_] == user_id
}

requester_roles contains role.name if {
  roles_array := object.get(cfg.user_roles, "roles", [])
  role := roles_array[_]
  role.members[_] == requester_identity
}

requester_has_role(role_name) if {
  requester_roles[role_name]
}

# -------------------------
# Business hours check
# -------------------------

# Parse timezone string like "UTC-8" or "UTC+8" to numeric offset
parse_timezone_offset(tz_string) = offset if {
  startswith(tz_string, "UTC")
  tz_part := substring(tz_string, 3, -1)
  # Handle negative offset like "-6"
  offset := to_number(tz_part)
}

parse_timezone_offset(tz_string) = 0 if {
  not startswith(tz_string, "UTC")
}

current_hour := hour if {
  # Explicit timestamp provided - treat as UTC
  timestamp := input.timestamp
  ns_per_hour := 3600000000000
  hours_since_epoch := timestamp / ns_per_hour
  hour := hours_since_epoch % 24
}

current_hour := hour if {
  # No timestamp provided - use current time with timezone offset
  not input.timestamp
  timestamp := time.now_ns()
  ns_per_hour := 3600000000000
  hours_since_epoch := timestamp / ns_per_hour
  utc_hour := hours_since_epoch % 24
  timezone_string := object.get(cfg.business_hours, "timezone", "UTC+0")
  timezone_offset := parse_timezone_offset(timezone_string)
  hour := (utc_hour + timezone_offset + 24) % 24
}

is_within_business_hours if {
  business_hours := cfg.business_hours
  start_hour := object.get(business_hours, "start_hour", 9)
  end_hour := object.get(business_hours, "end_hour", 18)
  current_hour >= start_hour
  current_hour < end_hour
}

is_send_action if { tool_name == "send_email" }
is_send_action if { tool_name == "gmail_send_email" }

# -------------------------
# Recipient extraction
# -------------------------

recipient_candidates contains val if {
  to_value := object.get(tool_args, "to", null)
  is_array(to_value)
  val := to_value[_]
}

recipient_candidates contains val if {
  to_value := object.get(tool_args, "to", null)
  is_string(to_value)
  val := to_value
}

recipient_candidates contains val if {
  cc_value := object.get(tool_args, "cc", null)
  is_array(cc_value)
  val := cc_value[_]
}

recipient_candidates contains val if {
  cc_value := object.get(tool_args, "cc", null)
  is_string(cc_value)
  val := cc_value
}

recipient_candidates contains val if {
  bcc_value := object.get(tool_args, "bcc", null)
  is_array(bcc_value)
  val := bcc_value[_]
}

recipient_candidates contains val if {
  bcc_value := object.get(tool_args, "bcc", null)
  is_string(bcc_value)
  val := bcc_value
}

recipient_candidates contains val if {
  message := object.get(tool_args, "message", {})
  to_value := object.get(message, "to", null)
  is_array(to_value)
  val := to_value[_]
}

recipient_candidates contains val if {
  message := object.get(tool_args, "message", {})
  to_value := object.get(message, "to", null)
  is_string(to_value)
  val := to_value
}

recipient_candidates contains val if {
  message := object.get(tool_args, "message", {})
  cc_value := object.get(message, "cc", null)
  is_array(cc_value)
  val := cc_value[_]
}

recipient_candidates contains val if {
  message := object.get(tool_args, "message", {})
  cc_value := object.get(message, "cc", null)
  is_string(cc_value)
  val := cc_value
}

recipient_candidates contains val if {
  message := object.get(tool_args, "message", {})
  bcc_value := object.get(message, "bcc", null)
  is_array(bcc_value)
  val := bcc_value[_]
}

recipient_candidates contains val if {
  message := object.get(tool_args, "message", {})
  bcc_value := object.get(message, "bcc", null)
  is_string(bcc_value)
  val := bcc_value
}

normalized_recipients contains addr if {
  is_send_action
  raw := recipient_candidates[_]
  trimmed := lower(trim_ws(raw))
  trimmed != ""
  addr := trimmed
}

recipient_count := count(normalized_recipients)

# -------------------------
# Email content
# -------------------------

subject := trim_ws(object.get(
  tool_args,
  "subject",
  object.get(object.get(tool_args, "message", {}), "subject", "")
))

body := sprintf("%v", [
  object.get(
    tool_args,
    "body",
    object.get(
      object.get(tool_args, "message", {}),
      "body",
      object.get(object.get(tool_args, "message", {}), "text", "")
    )
  )
])

recipient_domain(addr) = domain if {
  parts := split(addr, "@")
  count(parts) == 2
  domain := lower(trim_ws(parts[1]))
}

recipient_domain(addr) = "" if {
  not contains(addr, "@")
}

external_recipient_present if {
  normalized_recipients[addr]
  not is_allowed_recipient(addr)
}

is_allowed_recipient(addr) if {
  domain := recipient_domain(addr)
  cfg.internal_domains[_] == domain
}

is_allowed_recipient(addr) if {
  cfg.allowed_external_emails[_] == addr
}

# -------------------------
# Deny logic
# -------------------------

deny_reasons contains reason if {
  is_send_action
  normalized_recipients[recipient]
  soc_team := object.get(cfg.teams, "soc_team", {})
  members := object.get(soc_team, "members", [])
  members[_] == recipient
  not is_within_business_hours
  reason := sprintf("soc_team_email_outside_business_hours:%s", [recipient])
}

deny_reasons contains reason if {
  is_send_action
  normalized_recipients[recipient]
  soc_team := object.get(cfg.teams, "soc_team", {})
  members := object.get(soc_team, "members", [])
  members[_] == recipient
  not requester_has_role("soc_analyst")
  reason := sprintf("soc_analyst_role_required_to_email_soc_team:%s", [recipient])
}

deny_reasons contains reason if {
  is_send_action
  normalized_recipients[recipient]
  cfg.blocked_recipients[_] == recipient
  reason := sprintf("blocked_recipient:%s", [recipient])
}

deny_reasons contains reason if {
  is_send_action
  normalized_recipients[recipient]
  not is_allowed_recipient(recipient)
  reason := sprintf("external_recipient_not_allowed:%s", [recipient])
}

deny_reasons contains reason if {
  is_send_action
  normalized_recipients[recipient]
  pattern := cfg.broadcast_patterns[_]
  regex.match(pattern, recipient)
  not is_broadcast_privileged
  reason := sprintf("broadcast_requires_privileged_identity:%s", [recipient])
}

deny_reasons contains reason if {
  is_send_action
  recipient_count > cfg.max_recipients
  reason := sprintf("max_recipients_exceeded:%d>%d", [recipient_count, cfg.max_recipients])
}

deny_reasons contains reason if {
  is_send_action
  cfg.require_nonempty_subject
  subject == ""
  reason := "subject_required"
}

deny_reasons contains reason if {
  is_send_action
  count(body) > cfg.max_body_chars
  reason := sprintf("body_too_large:%d>%d", [count(body), cfg.max_body_chars])
}

is_broadcast_privileged if {
  cfg.broadcast_allowed_identities[_] == requester_identity
}

# -------------------------
# Allow logic
# -------------------------

allow if { not is_send_action }

allow if {
  is_send_action
  count(deny_reasons) == 0
}

# -------------------------
# Decision computation
# -------------------------

sorted_reasons := sort([r | deny_reasons[r]])

reason = "ok" if { allow }

reason = sorted_reasons[0] if {
  count(sorted_reasons) > 0
}

require_approval if {
  is_send_action
  allow
  recipient_count > 5
}

require_approval if {
  is_send_action
  allow
  external_recipient_present
}

risk = "high" if { count(deny_reasons) > 0 }

risk = "medium" if {
  count(deny_reasons) == 0
  is_send_action
  require_approval
}

risk = "low" if {
  count(deny_reasons) == 0
  not require_approval
}

decision_label = "DENY" if { not allow }

decision_label = "REQUIRE_APPROVAL" if {
  allow
  require_approval
}

decision_label = "ALLOW" if {
  allow
  not require_approval
}

decision = {
  "allow": allow,
  "decision": decision_label,
  "reason": reason,
  "reasons": sorted_reasons,
  "risk": risk
}
