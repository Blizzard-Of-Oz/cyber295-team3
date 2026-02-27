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

# -------------------------
# Business hours calculation
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
  # If explicit timestamp provided in nanoseconds (for demo/testing) - treat as UTC
  timestamp := input.timestamp
  ns_per_hour := 3600000000000
  hours_since_epoch := floor(timestamp / ns_per_hour)
  hour := hours_since_epoch % 24
}

current_hour := hour if {
  # No timestamp provided - use current OPA server time (production mode)
  not input.timestamp
  timestamp := time.now_ns()
  ns_per_hour := 3600000000000
  hours_since_epoch := floor(timestamp / ns_per_hour)
  hour := hours_since_epoch % 24
}

is_working_hours if {
  business_hours := cfg.business_hours
  start_hour := object.get(business_hours, "start_hour", 9)
  end_hour := object.get(business_hours, "end_hour", 18)
  timezone_string := object.get(business_hours, "timezone", "UTC+0")
  timezone_offset := parse_timezone_offset(timezone_string)
  start_hour_utc := (start_hour - timezone_offset + 24) % 24
  end_hour_utc := (end_hour - timezone_offset + 24) % 24
  # Handle both normal and wrap-around ranges after UTC conversion
  start_hour_utc < end_hour_utc
  current_hour >= start_hour_utc
  current_hour < end_hour_utc
}

is_working_hours if {
  business_hours := cfg.business_hours
  start_hour := object.get(business_hours, "start_hour", 9)
  end_hour := object.get(business_hours, "end_hour", 18)
  timezone_string := object.get(business_hours, "timezone", "UTC+0")
  timezone_offset := parse_timezone_offset(timezone_string)
  start_hour_utc := (start_hour - timezone_offset + 24) % 24
  end_hour_utc := (end_hour - timezone_offset + 24) % 24
  # Wrap-around window (e.g., 22 -> 6)
  start_hour_utc >= end_hour_utc
  current_hour >= start_hour_utc
}

is_working_hours if {
  business_hours := cfg.business_hours
  start_hour := object.get(business_hours, "start_hour", 9)
  end_hour := object.get(business_hours, "end_hour", 18)
  timezone_string := object.get(business_hours, "timezone", "UTC+0")
  timezone_offset := parse_timezone_offset(timezone_string)
  start_hour_utc := (start_hour - timezone_offset + 24) % 24
  end_hour_utc := (end_hour - timezone_offset + 24) % 24
  # Wrap-around window (e.g., 22 -> 6)
  start_hour_utc >= end_hour_utc
  current_hour < end_hour_utc
}


default allow = false

default decision_outcome = "DENY"
default risk = "medium"
default cooldown_seconds = 0

requester_role := object.get(input.requester, "role", "unknown")
requester_identity := lower(object.get(input.requester, "identity", "unknown"))

recipient_count := object.get(input.context, "recipient_count", 0)
is_companywide := object.get(input.context, "is_companywide", false)
urgency_score := object.get(input.context, "urgency_score", 0)
has_prompt_injection := object.get(input.context, "has_prompt_injection", false)
attachment_bytes := object.get(input.context, "attachment_bytes", 0)
data_classification := object.get(input.context, "data_classification", "none")
employment_status := object.get(input.context, "employment_status", "active")
record_count := object.get(input.context, "record_count", 0)

recipients := object.get(input.context, "recipients", [])
recipient_domains := object.get(input.context, "recipient_domains", [])

any_personal_domain if {
  some d in recipient_domains
  d in cfg.personal_domains
}

any_external_domain if {
  some d in recipient_domains
  not d in cfg.internal_domains
}

trusted_sender if {
  requester_identity in cfg.trusted_senders
}

role_limit := object.get(cfg.role_recipient_limits, requester_role, 25)

recipient_limit_exceeded if {
  recipient_count > role_limit
}

broadcast_privilege_denied if {
  is_companywide
  not requester_role in cfg.broadcast_allowed_roles
}

blocked_external_recipient if {
  some r in recipients
  rr := lower(r)
  contains(rr, "@")
  not rr in cfg.allowed_external_emails
  parts := split(rr, "@")
  domain := parts[count(parts)-1]
  not domain in cfg.internal_domains
}

after_hours_personal_domain if {
  not is_working_hours
  some r in recipients
  rr := lower(r)
  not rr in cfg.allowed_external_emails
  parts := split(rr, "@")
  domain := parts[count(parts)-1]
  domain in cfg.personal_domains
}

after_hours_bulk_exfil if {
  not is_working_hours
  any_personal_domain
  attachment_bytes > cfg.after_hours_attachment_limit_bytes
}

departing_employee_exfil if {
  employment_status == "notice_period"
  any_personal_domain
  data_classification == "confidential"
}

departing_employee_exfil if {
  employment_status == "notice_period"
  any_personal_domain
  attachment_bytes > 0
}

bulk_customer_export if {
  data_classification == "confidential"
  record_count >= 100
}

high_urgency_untrusted if {
  urgency_score >= cfg.urgency_threshold
  not trusted_sender
}

triggered_controls[c] if {
  high_urgency_untrusted
  c := "urgency_throttle_triggered"
}

triggered_controls[c] if {
  has_prompt_injection
  c := "prompt_injection_detected"
}

triggered_controls[c] if {
  blocked_external_recipient
  c := "external_recipient_not_approved"
}

triggered_controls[c] if {
  broadcast_privilege_denied
  c := "broadcast_requires_privileged_role"
}

triggered_controls[c] if {
  recipient_limit_exceeded
  c := "recipient_limit_exceeded"
}

triggered_controls[c] if {
  after_hours_personal_domain
  c := "after_hours_personal_domain_blocked"
}

triggered_controls[c] if {
  after_hours_bulk_exfil
  c := "after_hours_bulk_exfil_attempt"
}

triggered_controls[c] if {
  departing_employee_exfil
  c := "notice_period_protection"
}

triggered_controls[c] if {
  bulk_customer_export
  c := "bulk_customer_export_detected"
}

deny_reasons[r] if {
  has_prompt_injection
  r := "Prompt injection pattern \"IGNORE PREVIOUS INSTRUCTIONS\" detected."
}

deny_reasons[r] if {
  blocked_external_recipient
  r := "External recipient is not approved."
}

deny_reasons[r] if {
  broadcast_privilege_denied
  r := "Insufficient privileges for company-wide email."
}

deny_reasons[r] if {
  recipient_limit_exceeded
  r := sprintf("Recipient count exceeds limit for role %s.", [requester_role])
}

deny_reasons[r] if {
  after_hours_personal_domain
  r := "Emails to personal domains are not allowed outside business hours."
}

deny_reasons[r] if {
  after_hours_bulk_exfil
  r := "After-hours personal-domain transfer with oversized attachment is blocked."
}

deny_reasons[r] if {
  departing_employee_exfil
  r := "Departing employee cannot send confidential data or attachments to personal domains."
}

deny_reasons[r] if {
  bulk_customer_export
  any_personal_domain
  r := "Bulk customer records cannot be sent to personal domains."
}

allow_reasons[r] if {
  r := "Request satisfies role, recipient, domain, and business-hour controls."
}

throttle_reasons[r] if {
  high_urgency_untrusted
  r := "High urgency score from untrusted sender; cooling-off period required."
}

decision_outcome = "DENY" if {
  count(deny_reasons) > 0
}

decision_outcome = "THROTTLE" if {
  count(deny_reasons) == 0
  high_urgency_untrusted
}

decision_outcome = "ALLOW" if {
  count(deny_reasons) == 0
  not high_urgency_untrusted
}

allow if {
  decision_outcome == "ALLOW"
}

reasons := rs if {
  decision_outcome == "DENY"
  rs := sort([r | deny_reasons[r]])
}

reasons := rs if {
  decision_outcome == "THROTTLE"
  rs := sort([r | throttle_reasons[r]])
}

reasons := rs if {
  decision_outcome == "ALLOW"
  rs := ["Allowed by policy"]
}

reason := reasons[0] if {
  count(reasons) > 0
}

reason := "Denied by policy" if {
  decision_outcome == "DENY"
  count(reasons) == 0
}

reason := "cooling-off period required" if {
  decision_outcome == "THROTTLE"
  count(reasons) == 0
}

reason := "Allowed by policy" if {
  decision_outcome == "ALLOW"
}

risk = "high" if {
  decision_outcome == "DENY"
}

risk = "medium" if {
  decision_outcome == "THROTTLE"
}

risk = "low" if {
  decision_outcome == "ALLOW"
}

cooldown_seconds = cfg.throttle_seconds if {
  decision_outcome == "THROTTLE"
}

actions[a] if {
  decision_outcome == "DENY"
  has_prompt_injection
  a := "ALERT_SECURITY"
}

actions[a] if {
  decision_outcome == "DENY"
  blocked_external_recipient
  a := "ALERT_SECURITY"
}

actions[a] if {
  decision_outcome == "DENY"
  after_hours_personal_domain
  a := "ALERT_SECURITY"
}

actions[a] if {
  decision_outcome == "DENY"
  after_hours_bulk_exfil
  a := "ALERT_SECURITY"
}

actions[a] if {
  decision_outcome == "DENY"
  departing_employee_exfil
  a := "ALERT_SECURITY"
}

actions[a] if {
  decision_outcome == "DENY"
  after_hours_bulk_exfil
  a := "LOCK_ACCOUNT"
}

actions[a] if {
  decision_outcome == "DENY"
  departing_employee_exfil
  a := "LOCK_ACCOUNT"
}

actions[a] if {
  decision_outcome == "DENY"
  departing_employee_exfil
  a := "MANAGER_LEGAL_REVIEW"
}

decision = {
  "allow": allow,
  "decision": decision_outcome,
  "reason": reason,
  "reasons": reasons,
  "actions": sort([a | actions[a]]),
  "cooldown_seconds": cooldown_seconds,
  "risk": risk,
  "policy_version": cfg.policy_version,
  "triggered_controls": sort([c | triggered_controls[c]])
}
