package gmail

default allow = false

default decision = {
  "allow": false,
  "decision": "DENY",
  "reason": "missing_decision",
  "reasons": ["missing_decision"],
  "risk": "high"
}

tool := object.get(input, "tool", {})
request := object.get(input, "request", {})
request_body := object.get(request, "body", {})
request_headers := object.get(request, "headers", {})

raw_tool_name := object.get(tool, "name", object.get(request_body, "name", ""))
tool_name := lower(trim(sprintf("%v", [raw_tool_name])))

tool_args := object.get(tool, "arguments", object.get(request_body, "arguments", {}))

requester_identity := lower(trim(sprintf("%v", [
  object.get(
    object.get(input, "requester", {}),
    "identity",
    object.get(request_headers, "x-authenticated-user", "")
  )
])))

is_send_action {
  tool_name == "send_email"
}

is_send_action {
  tool_name == "gmail_send_email"
}

normalized_recipients[addr] {
  is_send_action
  raw := recipient_candidates[_]
  trimmed := lower(trim(sprintf("%v", [raw])))
  trimmed != ""
  addr := trimmed
}

recipient_candidates[val] {
  to_value := object.get(tool_args, "to", null)
  values_from_field(to_value, val)
}

recipient_candidates[val] {
  cc_value := object.get(tool_args, "cc", null)
  values_from_field(cc_value, val)
}

recipient_candidates[val] {
  bcc_value := object.get(tool_args, "bcc", null)
  values_from_field(bcc_value, val)
}

recipient_candidates[val] {
  message := object.get(tool_args, "message", {})
  to_value := object.get(message, "to", null)
  values_from_field(to_value, val)
}

recipient_candidates[val] {
  message := object.get(tool_args, "message", {})
  cc_value := object.get(message, "cc", null)
  values_from_field(cc_value, val)
}

recipient_candidates[val] {
  message := object.get(tool_args, "message", {})
  bcc_value := object.get(message, "bcc", null)
  values_from_field(bcc_value, val)
}

values_from_field(field, value) {
  is_array(field)
  value := field[_]
}

values_from_field(field, value) {
  is_string(field)
  value := field
}

subject := trim(sprintf("%v", [
  object.get(
    tool_args,
    "subject",
    object.get(object.get(tool_args, "message", {}), "subject", "")
  )
]))

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

recipient_count := count(normalized_recipients)

recipient_domain(addr) = domain {
  parts := split(addr, "@")
  count(parts) == 2
  domain := lower(trim(parts[1]))
}

recipient_domain(addr) = "" {
  not contains(addr, "@")
}

external_recipient_present {
  normalized_recipients[addr]
  not is_allowed_recipient(addr)
}

is_allowed_recipient(addr) {
  domain := recipient_domain(addr)
  data.config.internal_domains[_] == domain
}

is_allowed_recipient(addr) {
  data.config.allowed_external_emails[_] == addr
}

deny_reasons[reason] {
  is_send_action
  normalized_recipients[recipient]
  data.config.blocked_recipients[_] == recipient
  reason := sprintf("blocked_recipient:%s", [recipient])
}

deny_reasons[reason] {
  is_send_action
  normalized_recipients[recipient]
  not is_allowed_recipient(recipient)
  reason := sprintf("external_recipient_not_allowed:%s", [recipient])
}

deny_reasons[reason] {
  is_send_action
  normalized_recipients[recipient]
  pattern := data.config.broadcast_patterns[_]
  regex.match(pattern, recipient)
  not is_broadcast_privileged
  reason := sprintf("broadcast_requires_privileged_identity:%s", [recipient])
}

deny_reasons[reason] {
  is_send_action
  recipient_count > data.config.max_recipients
  reason := sprintf("max_recipients_exceeded:%d>%d", [recipient_count, data.config.max_recipients])
}

deny_reasons[reason] {
  is_send_action
  data.config.require_nonempty_subject
  subject == ""
  reason := "subject_required"
}

deny_reasons[reason] {
  is_send_action
  count(body) > data.config.max_body_chars
  reason := sprintf("body_too_large:%d>%d", [count(body), data.config.max_body_chars])
}

is_broadcast_privileged {
  data.config.broadcast_allowed_identities[_] == requester_identity
}

allow {
  not is_send_action
}

allow {
  is_send_action
  count(deny_reasons) == 0
}

reason = "ok" {
  allow
}

reason = reasons[0] {
  reasons := sorted_reasons
  count(reasons) > 0
}

sorted_reasons := sort([r | deny_reasons[r]])

require_approval {
  is_send_action
  allow
  recipient_count > 5
}

require_approval {
  is_send_action
  allow
  external_recipient_present
}

risk = "high" {
  count(deny_reasons) > 0
}

risk = "medium" {
  count(deny_reasons) == 0
  is_send_action
  require_approval
}

risk = "low" {
  count(deny_reasons) == 0
  not require_approval
}

decision_label = "DENY" {
  not allow
}

decision_label = "REQUIRE_APPROVAL" {
  allow
  require_approval
}

decision_label = "ALLOW" {
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
