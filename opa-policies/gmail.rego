package gmail

default allow = false

default decision_outcome = "DENY"
default risk = "medium"
default cooldown_seconds = 0

policy_version := object.get(data, "policy_version", "v1")

requester_role := object.get(input.requester, "role", "unknown")
requester_identity := lower(object.get(input.requester, "identity", "unknown"))

recipient_count := object.get(input.context, "recipient_count", 0)
is_companywide := object.get(input.context, "is_companywide", false)
is_working_hours := object.get(input.context, "is_working_hours", true)
urgency_score := object.get(input.context, "urgency_score", 0)
has_prompt_injection := object.get(input.context, "has_prompt_injection", false)
attachment_bytes := object.get(input.context, "attachment_bytes", 0)
data_classification := object.get(input.context, "data_classification", "none")
employment_status := object.get(input.context, "employment_status", "active")
record_count := object.get(input.context, "record_count", 0)

recipients := object.get(input.context, "recipients", [])
recipient_domains := object.get(input.context, "recipient_domains", [])

any_personal_domain {
  some d in recipient_domains
  d in data.personal_domains
}

any_external_domain {
  some d in recipient_domains
  not d in data.internal_domains
}

trusted_sender {
  requester_identity in data.trusted_senders
}

role_limit := object.get(data.role_recipient_limits, requester_role, 25)

recipient_limit_exceeded {
  recipient_count > role_limit
}

broadcast_privilege_denied {
  is_companywide
  not requester_role in data.broadcast_allowed_roles
}

blocked_external_recipient {
  some r in recipients
  rr := lower(r)
  contains(rr, "@")
  not rr in data.allowed_external_emails
  parts := split(rr, "@")
  domain := parts[count(parts)-1]
  not domain in data.internal_domains
}

after_hours_bulk_exfil {
  not is_working_hours
  any_personal_domain
  attachment_bytes > data.after_hours_attachment_limit_bytes
}

departing_employee_exfil {
  employment_status == "notice_period"
  any_personal_domain
  (data_classification == "confidential" or attachment_bytes > 0)
}

bulk_customer_export {
  data_classification == "confidential"
  record_count >= 100
}

high_urgency_untrusted {
  urgency_score >= data.urgency_threshold
  not trusted_sender
}

triggered_controls[c] {
  high_urgency_untrusted
  c := "urgency_throttle_triggered"
}

triggered_controls[c] {
  has_prompt_injection
  c := "prompt_injection_detected"
}

triggered_controls[c] {
  blocked_external_recipient
  c := "external_recipient_not_approved"
}

triggered_controls[c] {
  broadcast_privilege_denied
  c := "broadcast_requires_privileged_role"
}

triggered_controls[c] {
  recipient_limit_exceeded
  c := "recipient_limit_exceeded"
}

triggered_controls[c] {
  after_hours_bulk_exfil
  c := "after_hours_bulk_exfil_attempt"
}

triggered_controls[c] {
  departing_employee_exfil
  c := "notice_period_protection"
}

triggered_controls[c] {
  bulk_customer_export
  c := "bulk_customer_export_detected"
}

deny_reasons[r] {
  has_prompt_injection
  r := "Prompt injection pattern \"IGNORE PREVIOUS INSTRUCTIONS\" detected."
}

deny_reasons[r] {
  blocked_external_recipient
  r := "External recipient is not approved."
}

deny_reasons[r] {
  broadcast_privilege_denied
  r := "Insufficient privileges for company-wide email."
}

deny_reasons[r] {
  recipient_limit_exceeded
  r := sprintf("Recipient count exceeds limit for role %s.", [requester_role])
}

deny_reasons[r] {
  after_hours_bulk_exfil
  r := "After-hours personal-domain transfer with oversized attachment is blocked."
}

deny_reasons[r] {
  departing_employee_exfil
  r := "Departing employee cannot send confidential data or attachments to personal domains."
}

deny_reasons[r] {
  bulk_customer_export
  any_personal_domain
  r := "Bulk customer records cannot be sent to personal domains."
}

allow_reasons[r] {
  r := "Request satisfies role, recipient, domain, and business-hour controls."
}

throttle_reasons[r] {
  high_urgency_untrusted
  r := "High urgency score from untrusted sender; cooling-off period required."
}

decision_outcome = "DENY" {
  count(deny_reasons) > 0
}

decision_outcome = "THROTTLE" {
  count(deny_reasons) == 0
  high_urgency_untrusted
}

decision_outcome = "ALLOW" {
  count(deny_reasons) == 0
  not high_urgency_untrusted
}

allow {
  decision_outcome == "ALLOW"
}

reasons := rs {
  decision_outcome == "DENY"
  rs := sort([r | deny_reasons[r]])
}

reasons := rs {
  decision_outcome == "THROTTLE"
  rs := sort([r | throttle_reasons[r]])
}

reasons := rs {
  decision_outcome == "ALLOW"
  rs := ["Allowed by policy"]
}

reason := r {
  some x in reasons
  r := x
}

reason := "Denied by policy" {
  decision_outcome == "DENY"
  count(reasons) == 0
}

reason := "cooling-off period required" {
  decision_outcome == "THROTTLE"
  count(reasons) == 0
}

risk = "high" {
  decision_outcome == "DENY"
}

risk = "medium" {
  decision_outcome == "THROTTLE"
}

risk = "low" {
  decision_outcome == "ALLOW"
}

cooldown_seconds = data.throttle_seconds {
  decision_outcome == "THROTTLE"
}

actions[a] {
  decision_outcome == "DENY"
  (has_prompt_injection or blocked_external_recipient)
  a := "ALERT_SECURITY"
}

actions[a] {
  decision_outcome == "DENY"
  (after_hours_bulk_exfil or departing_employee_exfil)
  a := "ALERT_SECURITY"
}

actions[a] {
  decision_outcome == "DENY"
  (after_hours_bulk_exfil or departing_employee_exfil)
  a := "LOCK_ACCOUNT"
}

actions[a] {
  decision_outcome == "DENY"
  departing_employee_exfil
  a := "MANAGER_LEGAL_REVIEW"
}

decision = {
  "allow": allow,
  "reason": reason,
  "decision": decision_outcome,
  "reasons": reasons,
  "actions": sort([a | actions[a]]),
  "cooldown_seconds": cooldown_seconds,
  "risk": risk,
  "policy_version": policy_version,
  "triggered_controls": sort([c | triggered_controls[c]])
}
