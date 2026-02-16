package gmail

import future.keywords

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
  data.config.internal_domains[_] == domain
}

is_allowed_recipient(addr) if {
  data.config.allowed_external_emails[_] == addr
}

# -------------------------
# Deny logic
# -------------------------

deny_reasons contains reason if {
  is_send_action
  normalized_recipients[recipient]
  data.config.blocked_recipients[_] == recipient
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
  pattern := data.config.broadcast_patterns[_]
  regex.match(pattern, recipient)
  not is_broadcast_privileged
  reason := sprintf("broadcast_requires_privileged_identity:%s", [recipient])
}

deny_reasons contains reason if {
  is_send_action
  recipient_count > data.config.max_recipients
  reason := sprintf("max_recipients_exceeded:%d>%d", [recipient_count, data.config.max_recipients])
}

deny_reasons contains reason if {
  is_send_action
  data.config.require_nonempty_subject
  subject == ""
  reason := "subject_required"
}

deny_reasons contains reason if {
  is_send_action
  count(body) > data.config.max_body_chars
  reason := sprintf("body_too_large:%d>%d", [count(body), data.config.max_body_chars])
}

is_broadcast_privileged if {
  data.config.broadcast_allowed_identities[_] == requester_identity
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
