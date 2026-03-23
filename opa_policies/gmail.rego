package gmail

import future.keywords

# =========================================================
# Agent Credential Firewall — Email (Gmail) Policy
# Use Cases Coverage Map
#
# UC1  Team email (internal) → ALLOW (baseline allow when no triggers)
# UC2  Company-wide/broadcast email → DENY unless privileged role
# UC3  High-urgency + untrusted sender → THROTTLE (cooldown)
# UC4  Prompt injection / exfil instructions → DENY
# UC5  (Reserved in this file) PII handling → DENY/REQUIRE_APPROVAL (gateway signal; add if needed)
# UC6  Geolocation / impossible travel → DENY (gateway signal; add if needed)
# UC7  Rate limiting / spam prevention → THROTTLE (gateway counters; add if needed)
# UC8  Confidential keywords to external → DENY
# UC9  Attachment policy (blocked types / oversized / etc.) → DENY (gateway signals; add if needed)
# UC10 Approval workflow (high-risk actions) → COMMENTED OUT PER REQUEST
#
# UC11–UC40 are implemented below with explicit sections.
# =========================================================


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

# -------------------------
# Defaults / outputs
# -------------------------

default allow = false

# Extended outcomes:
# DENY | QUARANTINE | REQUIRE_APPROVAL | THROTTLE | WARN | ALLOW
default decision_outcome = "DENY"
default risk = "medium"
default cooldown_seconds = 0

# -------------------------
# Identity / context
# -------------------------

# Look up user profile from user_db (single source of truth)
requester_identity := lower(object.get(input.requester, "identity", "unknown"))
user_profile := object.get(cfg.user_db, requester_identity, {})

# Extract user attributes from user_db, with defaults
requester_role := object.get(user_profile, "role", "unknown")
employment_status := object.get(user_profile, "employment_status", "active")
user_days_remaining := object.get(user_profile, "days_remaining", 0)
primary_language := object.get(user_profile, "primary_language", "en")
primary_email := object.get(user_profile, "primary_email", requester_identity)

ctx := object.get(input, "context", {})

tool := object.get(ctx, "tool", "email.send")
recipient_count := object.get(ctx, "recipient_count", 0)
attachment_bytes := object.get(ctx, "attachment_bytes", 0)
data_classification := object.get(ctx, "data_classification", "none")
record_count := object.get(ctx, "record_count", 0)

recipients := object.get(ctx, "recipients", [])
cc := object.get(ctx, "cc", [])
bcc := object.get(ctx, "bcc", [])

content_text := object.get(ctx, "content_text", "")
user_input := object.get(ctx, "user_input", "")

# Raw MCP request payload fields (for direct OPA request-based scanning)
request_body_payload := object.get(object.get(input, "request", {}), "body", {})
request_email_body := object.get(request_body_payload, "body", "")
request_email_subject := object.get(request_body_payload, "subject", "")

attachments := object.get(ctx, "attachments", [])
urls := object.get(ctx, "urls", [])

thread := object.get(ctx, "thread", {})
domain_risk := object.get(ctx, "domain_risk", {})
temporal := object.get(ctx, "temporal", {})
geo := object.get(ctx, "geo", {})
counters := object.get(ctx, "counters", {})
language := object.get(ctx, "language", {})
calendar := object.get(ctx, "calendar", {})
auth := object.get(ctx, "auth", {})
oauth := object.get(ctx, "oauth", {})
lolbin := object.get(ctx, "lolbin", {})
dependency := object.get(ctx, "dependency", {})
cloud_forwarding := object.get(ctx, "cloud_forwarding", {})
vendor := object.get(ctx, "vendor", {})
recipient_list := object.get(ctx, "recipient_list", {})
delegation := object.get(ctx, "delegation", {})
send_as := lower(object.get(ctx, "send_as", ""))

approval := object.get(ctx, "approval", {})
approval_token := object.get(approval, "token", "")

recipient_has_clevel := object.get(ctx, "recipient_has_clevel", false)
recalled_recently := object.get(ctx, "recalled_recently", false)
urgency_manipulation := object.get(ctx, "urgency_manipulation", false)

# Legacy pr-4-test behavior for runtime MCP payloads.
send_email_urgency_manipulation_block if {
  lower(object.get(object.get(input, "tool", {}), "name", "")) == "send_email"
  urgency_manipulation
}

# Extract domains from recipient email addresses
recipient_domains := {domain |
  some r in recipients
  contains(r, "@")
  parts := split(lower(r), "@")
  domain := parts[count(parts)-1]
}

# =========================================================
# UC1–UC10: NOTES + BASELINE CONTROLS
# =========================================================

# UC1 (Team email internal) — baseline allow path when no denies/throttles/warns
#   - achieved by default decision_outcome == ALLOW when no reasons triggered
#
# UC2 (Company-wide/broadcast email) — block unless privileged role
#   - is_companywide + broadcast_privilege_denied → deny_reasons
#
# UC3 (High urgency + untrusted sender) — throttle
#   - urgency_score + high_urgency_untrusted → throttle_reasons
#
# UC4 (Prompt injection) — deny
#   - has_prompt_injection → deny_reasons
#
# UC5 (PII handling) — not explicitly implemented in this file (add gateway signal & deny/approval if needed)
# UC6 (Geo anomalies) — not explicitly implemented in this file (add gateway signal & deny if needed)
# UC7 (Rate limiting) — not explicitly implemented in this file (add counters thresholds & throttle/deny if needed)
#
# UC8 (Confidential keywords to external) — deny
#   - confidential_keyword_found + any_external_domain → deny_reasons
#
# UC9 (Attachment policy restrictions) — not explicitly implemented in this file beyond spoofing/polyglot/archive/stego
#   - you can extend by adding blocked extensions / max size / malware flags to deny_reasons
#
# UC10 (Approval workflow) — COMMENTED OUT PER REQUEST
#   - The "needs_approval" detector and its reasons are commented out below.


# -------------------------
# Existing urgency scoring (UC3)
# -------------------------

# Compute urgency score from content and user input
# For each keyword that appears, add its weight to the score (counts once per keyword)
compute_urgency_score(text) = total if {
  text_lower := lower(text)
  scores := [cfg.urgency_keywords[kw] |
    some kw in object.keys(cfg.urgency_keywords)
    contains(text_lower, lower(kw))
  ]
  raw_total := sum(scores)
  total := min([10.0, raw_total])
}

urgency_score := score if {
  content_score := compute_urgency_score(content_text)
  user_input_score := compute_urgency_score(user_input)
  score := max([content_score, user_input_score])
}

# Determine if any recipient matches broadcast patterns from config (UC2)
is_companywide if {
  some r in recipients
  rr := lower(r)
  some pattern in cfg.broadcast_patterns
  regex.match(pattern, rr)
}

# Detect prompt injection by checking content and user input against injection patterns (UC4)
has_prompt_injection if {
  content_lower := lower(content_text)
  some pattern in cfg.injection_patterns
  pattern_lower := lower(pattern)
  contains(content_lower, pattern_lower)
}

has_prompt_injection if {
  user_input_lower := lower(user_input)
  some pattern in cfg.injection_patterns
  pattern_lower := lower(pattern)
  contains(user_input_lower, pattern_lower)
}

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

# unknown role, only 1 recipient allowed by default
role_limit := object.get(cfg.role_recipient_limits, requester_role, 1)

recipient_limit_exceeded if {
  recipient_count > role_limit
}

broadcast_privilege_denied if {
  is_companywide
  not requester_role in cfg.broadcast_allowed_roles
}

# External recipient allowlist / restrictions
blocked_external_recipient if {
  some r in recipients
  rr := lower(r)
  contains(rr, "@")
  not rr in cfg.allowed_external_emails
  parts := split(rr, "@")
  domain := parts[count(parts)-1]
  not domain in cfg.internal_domains
  not domain in cfg.personal_domains
}

blocked_external_recipient if {
  some r in recipients
  rr := lower(r)
  contains(rr, "@")
  not rr in cfg.allowed_external_emails
  parts := split(rr, "@")
  domain := parts[count(parts)-1]
  not domain in cfg.internal_domains
  domain in cfg.personal_domains
  not is_working_hours
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

# =========================================================
# UC11–UC40 DETECTORS (gateway-normalized signals)
# =========================================================

# ---------------------------------------------------------
# UC10 — Approval workflow (COMMENTED OUT)
# ---------------------------------------------------------

# UC10: approval workflow for high-risk actions (e.g., C-level, off-hours)
# needs_approval if {
#   recipient_has_clevel
#   not is_working_hours
#   approval_token == ""
# }

# ---------------------------------------------------------
# UC11 — Cross-tool coordination (reserved)
# Note: Typically enforced in gateway/orchestrator using shared counters / cross-tool context.
# ---------------------------------------------------------

# ---------------------------------------------------------
# UC12 — Document repository access (reserved)
# Note: Typically enforced via a separate policy package for docs/drive.
# ---------------------------------------------------------

# ---------------------------------------------------------
# UC13 — Reply-all bomb prevention
# ---------------------------------------------------------
reply_all_blocked if {
  tool == "email.reply_all"
  thread_recips := object.get(thread, "recipient_count", 0)
  thread_recips > 50
  not requester_role in object.get(cfg, "reply_all_allowed_roles", ["exec", "comms_director"])
}

# ---------------------------------------------------------
# UC14 — Domain typosquatting detection (gateway flags)
# UC40 — Unicode / homoglyph obfuscation (gateway flags)
# ---------------------------------------------------------
typosquat_or_homoglyph if {
  object.get(domain_risk, "typosquat_suspected", false)
} else if {
  object.get(domain_risk, "homoglyph_suspected", false)
}

# ---------------------------------------------------------
# UC15 — Temporal consistency check (gateway flags)
# ---------------------------------------------------------
temporal_mismatch if {
  not object.get(temporal, "user_active_at_claimed_time", true)
} else if {
  not object.get(temporal, "device_id_matches", true)
}

# ---------------------------------------------------------
# UC16 — Email threading manipulation (invalid references)
# ---------------------------------------------------------
thread_invalid_refs if {
  not object.get(thread, "reference_ids_valid", true)
}

# ---------------------------------------------------------
# UC17 — Recipient list expansion / poisoned list
# ---------------------------------------------------------
recipient_list_poisoned if {
  flagged := object.get(recipient_list, "flagged_external_recipients", [])
  count(flagged) > 0
}

# ---------------------------------------------------------
# UC18 — Forwarding chain limit
# ---------------------------------------------------------
forwarding_chain_blocked if {
  tool == "email.forward"
  fwd_count := object.get(ctx, "forward_count", 0)
  fwd_count > 3
} else if {
  tool == "email.forward"
  hops := object.get(ctx, "forward_external_hops", 0)
  hops > 0
  any_external_domain
}

# ---------------------------------------------------------
# UC19 — BCC abuse prevention
# ---------------------------------------------------------
bcc_abuse if {
  count(bcc) > 0
  not requester_role in object.get(cfg, "bcc_allowed_roles", ["exec","hr","legal"])
} else if {
  count(bcc) > 0
  some r in bcc
  contains(lower(r), "@")
  parts := split(lower(r), "@")
  d := parts[count(parts)-1]
  not d in cfg.internal_domains
}

# ---------------------------------------------------------
# UC20 — Recall race condition
# ---------------------------------------------------------
recall_race if {
  recalled_recently
}

# ---------------------------------------------------------
# UC21 — Attachment name/type mismatch (gateway metadata)
# UC39 — Polyglot file detection (gateway metadata)
# ---------------------------------------------------------
attachment_spoofing if {
  some a in attachments
  declared := lower(object.get(a, "file_ext", ""))
  actual := lower(object.get(a, "actual_ext", declared))
  declared != ""
  actual != ""
  declared != actual
}

polyglot_detected if {
  some a in attachments
  types := object.get(a, "detected_types", [])
  count(types) > 1
}

# ---------------------------------------------------------
# UC22 — Mailbox delegation abuse / send-as controls
# ---------------------------------------------------------
send_as_protected_prefix_requires_approval if {
  send_as != ""
  send_as != lower(primary_email)
  prefixes := object.get(cfg, "protected_send_as_prefixes", ["ceo@", "cfo@", "legal@"])
  some p in prefixes
  startswith(send_as, lower(p))
  approval_token == ""
}

send_as_without_valid_delegation_requires_approval if {
  send_as != ""
  send_as != lower(primary_email)
  not object.get(delegation, "allowed", false)
  approval_token == ""
}

# ---------------------------------------------------------
# UC23 — Language/locale anomaly (WARN)
# ---------------------------------------------------------
language_anomaly if {
  detected := lower(object.get(language, "detected", primary_language))
  seen_before := object.get(language, "seen_before", true)
  detected != lower(primary_language)
  not seen_before
}

# ---------------------------------------------------------
# UC24 — Calendar invite injection (.ics)
# ---------------------------------------------------------
calendar_malicious if {
  object.get(calendar, "ics_detected", false)
  object.get(calendar, "malicious", false)
}

# ---------------------------------------------------------
# UC25 — Email metadata tampering (SPF/DKIM/DMARC failures)
# ---------------------------------------------------------
email_auth_failed if {
  not object.get(auth, "spf_pass", true)
} else if {
  not object.get(auth, "dkim_pass", true)
} else if {
  not object.get(auth, "dmarc_pass", true)
}

# ---------------------------------------------------------
# UC26 — Urgency exploitation (gateway flag) + existing throttle
# ---------------------------------------------------------
urgency_exploitation if {
  urgency_manipulation
} else if {
  urgency_score >= cfg.urgency_threshold
  not trusted_sender
}

# ---------------------------------------------------------
# UC27 — Steganographic data hiding (gateway score)
# ---------------------------------------------------------
stego_detected if {
  threshold := object.get(cfg, "stego_score_threshold", 0.8)
  some a in attachments
  score := object.get(a, "image_stego_score", 0.0)
  score >= threshold
}

# ---------------------------------------------------------
# UC28 — DNS tunneling via email links (entropy/length/base64)
dns_tunneling_url if {
  thresh := object.get(cfg, "subdomain_entropy_threshold", 4.5)
  some u in urls
  entropy := object.get(u, "subdomain_entropy", 0.0)
  slen := object.get(u, "subdomain_length", 0)
  looks_b64 := object.get(u, "looks_base64", false)
  slen > 32
}
# ---------------------------------------------------------
dns_tunneling_url if {
  thresh := object.get(cfg, "subdomain_entropy_threshold", 4.5)
  some u in urls
  entropy := object.get(u, "subdomain_entropy", 0.0)
  entropy >= thresh
}
dns_tunneling_url if {
  thresh := object.get(cfg, "subdomain_entropy_threshold", 4.5)
  some u in urls
  looks_b64 := object.get(u, "looks_base64", false)
  looks_b64
}

# ---------------------------------------------------------
# UC29 — Chunked/low-and-slow exfil (gateway counters)
# ---------------------------------------------------------
chunked_exfil if {
  any_personal_domain
  to24 := object.get(counters, "emails_to_same_recipient_last_24h", 0)
  vol := object.get(counters, "aggregate_data_volume_to_recipient_24h_bytes", 0)
  max_emails := object.get(cfg, "max_emails_to_same_external_24h", 20)
  max_bytes := object.get(cfg, "max_aggregate_bytes_to_same_external_24h", 500000)
  to24 > max_emails
  vol > max_bytes
}

# ---------------------------------------------------------
# UC30 — Compressed archive exfiltration (gateway flags)
# ---------------------------------------------------------
archive_policy := object.get(cfg, "archive_policy", {})

archive_blocked_file_types := exts if {
  configured := object.get(archive_policy, "blocked_file_types", ["exe", "dll", "js", "vbs", "ps1", "bat", "cmd", "scr", "jar"])
  exts := {normalized |
    some ext in configured
    type_name(ext) == "string"
    ext_lower := lower(ext)
    normalized := trim_prefix(ext_lower, ".")
    normalized != ""
  }
}

archive_min_blocked_type_matches := object.get(archive_policy, "min_blocked_type_matches", 1)
archive_max_file_count := object.get(archive_policy, "max_file_count", 1000)
archive_max_compression_ratio := object.get(archive_policy, "max_compression_ratio", 15.0)
archive_block_password_protected := object.get(archive_policy, "block_password_protected", true)
archive_password_protected_requires_external := object.get(archive_policy, "password_protected_requires_external", true)

archive_extension_set := exts if {
  configured := object.get(cfg, "archive_extensions", ["zip", "7z", "rar", "tar", "gz", "tgz", "bz2", "xz"])
  exts := {normalized |
    some ext in configured
    ext_lower := lower(ext)
    normalized := trim_prefix(ext_lower, ".")
    normalized != ""
  }
}

attachment_is_archive(a) if {
  declared := lower(trim_prefix(object.get(a, "file_ext", ""), "."))
  declared != ""
  declared in archive_extension_set
} else if {
  actual := lower(trim_prefix(object.get(a, "actual_ext", ""), "."))
  actual != ""
  actual in archive_extension_set
}

archive_contains_file_types_for_attachment(a) := types if {
  archive_obj := object.get(a, "archive", {})
  raw_types := object.get(archive_obj, "contains_file_types", [])
  types := [normalized |
    some t in raw_types
    type_name(t) == "string"
    t_lower := lower(t)
    normalized := trim_prefix(t_lower, ".")
    normalized != ""
  ]
}

archive_file_count_for_attachment(a) := object.get(object.get(a, "archive", {}), "file_count", 0)

archive_password_protected_for_attachment(a) if {
  object.get(object.get(a, "archive", {}), "password_protected", false)
} else if {
  # Backward compatibility with legacy flat metadata field
  object.get(a, "archive_password_protected", false)
}

archive_compression_ratio_for_attachment(a) := object.get(object.get(a, "archive", {}), "compression_ratio", 0)

archive_contains_prohibited_for_attachment(a) if {
  types := archive_contains_file_types_for_attachment(a)
  blocked := {t |
    some t in types
    t in archive_blocked_file_types
  }
  count(blocked) >= archive_min_blocked_type_matches
}

archive_contains_prohibited_for_attachment(a) if {
  file_count := archive_file_count_for_attachment(a)
  type_name(file_count) == "number"
  file_count > archive_max_file_count
}

archive_contains_prohibited_for_attachment(a) if {
  archive_block_password_protected
  archive_password_protected_for_attachment(a)
  not archive_password_protected_requires_external
}

archive_contains_prohibited_for_attachment(a) if {
  archive_block_password_protected
  archive_password_protected_for_attachment(a)
  archive_password_protected_requires_external
  any_external_domain
}

archive_contains_prohibited_for_attachment(a) if {
  ratio := archive_compression_ratio_for_attachment(a)
  type_name(ratio) == "number"
  ratio >= archive_max_compression_ratio
}

archive_exfil if {
  some a in attachments
  attachment_is_archive(a)
  archive_contains_prohibited_for_attachment(a)
}

# Block direct attachments when extension matches archive_policy.blocked_file_types.
direct_blocked_attachment if {
  some a in attachments
  not attachment_is_archive(a)
  declared := lower(trim_prefix(object.get(a, "file_ext", ""), "."))
  declared != ""
  declared in archive_blocked_file_types
}

direct_blocked_attachment if {
  some a in attachments
  not attachment_is_archive(a)
  actual := lower(trim_prefix(object.get(a, "actual_ext", ""), "."))
  actual != ""
  actual in archive_blocked_file_types
}

direct_blocked_attachment if {
  some a in attachments
  not attachment_is_archive(a)
  name := lower(object.get(a, "name", ""))
  contains(name, ".")
  parts := split(name, ".")
  ext := parts[count(parts)-1]
  ext != ""
  ext in archive_blocked_file_types
}

# ---------------------------------------------------------
# UC31 — Email-to-cloud storage forwarding (gateway flag)
# ---------------------------------------------------------
cloud_forwarding_detected if {
  object.get(cloud_forwarding, "detected", false)
}

# ---------------------------------------------------------
# UC32 — Multi-stage payload delivery (redirects / executable)
# ---------------------------------------------------------
multi_stage_payload if {
  some u in urls
  redirects := object.get(u, "redirects", 0)
  redirects > 2
}

multi_stage_payload if {
  some u in urls
  serves_exec := object.get(u, "serves_executable", false)
  serves_exec
}
# ---------------------------------------------------------
# UC33 — LOLBin instructions (gateway flag)
# ---------------------------------------------------------
lolbin_detected if {
  object.get(lolbin, "detected", false)
}

# ---------------------------------------------------------
# UC34 — OAuth phishing (gateway analysis)
# ---------------------------------------------------------

oauth_phishing if {
  object.get(oauth, "detected", false)
  not object.get(oauth, "approved_client", true)
}

oauth_phishing if {
  object.get(oauth, "detected", false)
  object.get(oauth, "high_risk_scopes", false)
}

oauth_phishing if {
  object.get(oauth, "detected", false)
  not object.get(oauth, "redirect_trusted", true)
}

# ---------------------------------------------------------
# UC35 — After-hours bulk export (already covered by after_hours_bulk_exfil)
# ---------------------------------------------------------

# ---------------------------------------------------------
# UC36 — Departing employee data collection (already covered by departing_employee_exfil)
# ---------------------------------------------------------

# ---------------------------------------------------------
# UC37 — Compromised vendor account (BEC) → QUARANTINE (gateway flags)
# ---------------------------------------------------------
vendor_bec_suspected if {
  object.get(vendor, "trusted_vendor_sender", false)
  object.get(vendor, "payment_details_mismatch", false)
}

# ---------------------------------------------------------
# UC38 — Dependency confusion via email (gateway flag)
# ---------------------------------------------------------
dependency_confusion if {
  object.get(dependency, "detected", false)
}

# ---------------------------------------------------------
# UC8 — Confidential keywords (deny external sharing)
# ---------------------------------------------------------
attachment_extracted_texts := [txt |
  some a in attachments
  txt := object.get(a, "extracted_text", "")
  type_name(txt) == "string"
  trim_space(txt) != ""
]

confidential_scan_text := concat("\n", [
  content_text,
  object.get(ctx, "subject", ""),
  request_email_body,
  request_email_subject,
  concat("\n", attachment_extracted_texts),
])

confidential_keyword_found if {
  kws := object.get(cfg, "confidential_keywords", [])
  some kw in kws
  kw_trimmed := trim_space(kw)
  kw_trimmed != ""
  contains(lower(confidential_scan_text), lower(kw_trimmed))
}

confidential_pattern_found if {
  patterns := object.get(cfg, "confidential_regex_patterns", [])
  some p in patterns
  pattern := trim_space(p)
  pattern != ""
  regex.match(pattern, confidential_scan_text)
}

confidential_data_found if { confidential_keyword_found }
confidential_data_found if { confidential_pattern_found }

# =========================================================
# Triggered controls (telemetry)
# =========================================================

triggered_controls[c] if { high_urgency_untrusted; c := "urgency_throttle_triggered" }
triggered_controls[c] if { send_email_urgency_manipulation_block; c := "send_email_urgency_manipulation_denied" }
triggered_controls[c] if { has_prompt_injection; c := "prompt_injection_detected" }
triggered_controls[c] if { blocked_external_recipient; c := "external_recipient_not_approved" }
triggered_controls[c] if { broadcast_privilege_denied; c := "broadcast_requires_privileged_role" }
triggered_controls[c] if { recipient_limit_exceeded; c := "recipient_limit_exceeded" }
triggered_controls[c] if { after_hours_personal_domain; c := "after_hours_personal_domain_blocked" }
triggered_controls[c] if { after_hours_bulk_exfil; c := "after_hours_bulk_exfil_attempt" }
triggered_controls[c] if { departing_employee_exfil; c := "notice_period_protection" }
triggered_controls[c] if { bulk_customer_export; c := "bulk_customer_export_detected" }

# UC10 triggers are commented out (per request)
# triggered_controls[c] if { needs_approval; c := "step_up_approval_required" }

triggered_controls[c] if { reply_all_blocked; c := "reply_all_blocked" }                   # UC13
triggered_controls[c] if { typosquat_or_homoglyph; c := "typosquat_or_homoglyph_detected" } # UC14/UC40
triggered_controls[c] if { temporal_mismatch; c := "temporal_mismatch_detected" }          # UC15
triggered_controls[c] if { thread_invalid_refs; c := "thread_reference_invalid" }          # UC16
triggered_controls[c] if { recipient_list_poisoned; c := "recipient_list_poisoned" }       # UC17
triggered_controls[c] if { forwarding_chain_blocked; c := "forwarding_chain_blocked" }     # UC18
triggered_controls[c] if { bcc_abuse; c := "bcc_abuse_blocked" }                           # UC19
triggered_controls[c] if { recall_race; c := "recall_race_detected" }                       # UC20
triggered_controls[c] if { attachment_spoofing; c := "attachment_extension_mismatch" }     # UC21
triggered_controls[c] if { polyglot_detected; c := "polyglot_file_detected" }              # UC39
triggered_controls[c] if { calendar_malicious; c := "calendar_invite_malicious" }          # UC24
triggered_controls[c] if { email_auth_failed; c := "email_auth_failed" }                   # UC25
triggered_controls[c] if { stego_detected; c := "steganography_detected" }                 # UC27
triggered_controls[c] if { dns_tunneling_url; c := "dns_tunneling_url_detected" }          # UC28
triggered_controls[c] if { chunked_exfil; c := "chunked_exfil_detected" }                  # UC29
triggered_controls[c] if { archive_exfil; c := "archive_exfil_detected" }                  # UC30
triggered_controls[c] if { direct_blocked_attachment; c := "blocked_direct_attachment_detected" } # UC9
triggered_controls[c] if { cloud_forwarding_detected; c := "cloud_forwarding_detected" }   # UC31
triggered_controls[c] if { multi_stage_payload; c := "multi_stage_payload_detected" }      # UC32
triggered_controls[c] if { lolbin_detected; c := "lolbin_detected" }                       # UC33
triggered_controls[c] if { oauth_phishing; c := "oauth_phishing_detected" }                # UC34
triggered_controls[c] if { vendor_bec_suspected; c := "vendor_bec_quarantine" }            # UC37
triggered_controls[c] if { dependency_confusion; c := "dependency_confusion_detected" }    # UC38
triggered_controls[c] if { language_anomaly; c := "language_anomaly_warn" }                # UC23
triggered_controls[c] if { confidential_keyword_found; c := "confidential_keyword_found" } # UC8
triggered_controls[c] if { confidential_pattern_found; c := "confidential_pattern_found" } # UC8

# =========================================================
# Reasons
# =========================================================
deny_reasons[r] if {
  send_email_urgency_manipulation_block
  r := "urgency manipulation detected"
}

deny_reasons[r] if {
  has_prompt_injection
  content_lower := lower(content_text)
  some pattern in cfg.injection_patterns
  contains(content_lower, lower(pattern))
  r := sprintf("Prompt injection pattern detected in email: \"%s\"", [pattern])
}

deny_reasons[r] if {
  has_prompt_injection
  user_input_lower := lower(user_input)
  some pattern in cfg.injection_patterns
  contains(user_input_lower, lower(pattern))
  r := sprintf("Prompt injection pattern detected in user input: \"%s\"", [pattern])
}

deny_reasons[r] if { blocked_external_recipient; r := "External recipient is not approved." }
deny_reasons[r] if { broadcast_privilege_denied; r := "Insufficient privileges for company-wide email." }
deny_reasons[r] if { recipient_limit_exceeded; r := sprintf("Recipient count exceeds limit for role %s.", [requester_role]) }
deny_reasons[r] if { after_hours_personal_domain; r := "Emails to personal domains are not allowed outside business hours." }
deny_reasons[r] if { after_hours_bulk_exfil; r := "After-hours personal-domain transfer with oversized attachment is blocked." }
deny_reasons[r] if { departing_employee_exfil; r := "Departing employee cannot send confidential data or attachments to personal domains." }
deny_reasons[r] if { bulk_customer_export; any_personal_domain; r := "Bulk customer records cannot be sent to personal domains." }

# UC13–UC40 denies
deny_reasons[r] if { reply_all_blocked; r := "Reply-all blocked: distribution list too large for requester role." } # UC13
deny_reasons[r] if { typosquat_or_homoglyph; r := "Potential typosquatting / homoglyph domain detected." }          # UC14/UC40
deny_reasons[r] if { temporal_mismatch; r := "Temporal/session mismatch detected (user not active or device mismatch)." } # UC15
deny_reasons[r] if { thread_invalid_refs; r := "Thread references invalid (possible thread hijacking / forged headers)." } # UC16
deny_reasons[r] if { recipient_list_poisoned; r := "Unauthorized external recipient(s) detected in an internal recipient list." } # UC17
deny_reasons[r] if { forwarding_chain_blocked; r := "Forwarding chain policy violation (too many forwards or external hop)." } # UC18
deny_reasons[r] if { bcc_abuse; r := "BCC blocked (role not allowed or external BCC prohibited)." } # UC19
deny_reasons[r] if { recall_race; r := "Email was recalled recently; resend requires explicit approval." } # UC20
deny_reasons[r] if { attachment_spoofing; r := "Attachment extension mismatch / spoofing detected." } # UC21
deny_reasons[r] if { polyglot_detected; r := "Polyglot file detected (multiple valid formats) - possible scanner evasion." } # UC39
deny_reasons[r] if { calendar_malicious; r := "Malicious calendar invite detected." } # UC24
deny_reasons[r] if { email_auth_failed; any_external_domain; r := "Email authentication failed (SPF/DKIM/DMARC) for external send." } # UC25
deny_reasons[r] if { stego_detected; r := "Steganography signal indicates hidden data in image attachment." } # UC27
deny_reasons[r] if { dns_tunneling_url; r := "URL appears to contain encoded data (DNS tunneling / high-entropy subdomain)." } # UC28
deny_reasons[r] if {
  lower(object.get(object.get(input, "tool", {}), "name", "")) == "send_email"
  some u in urls
  object.get(u, "suspicious_query_payload", false)
  r := "suspicious encoded url payload detected"
}
deny_reasons[r] if {
  lower(object.get(object.get(input, "tool", {}), "name", "")) == "send_email"
  object.get(ctx, "dns_tunneling_detected", false)
  some u in urls
  object.get(u, "suspicious_domain_pattern", false)
  r := "dns tunneling / suspicious c2 domain detected"
}
deny_reasons[r] if {
  lower(object.get(object.get(input, "tool", {}), "name", "")) == "send_email"
  some u in urls
  object.get(u, "suspicious_hostname_pattern", false)
  r := "suspicious exfiltration domain detected"
}
deny_reasons[r] if {
  lower(object.get(object.get(input, "tool", {}), "name", "")) == "send_email"
  some u in urls
  object.get(u, "looks_base64_subdomain", false)
  r := "dns tunneling / suspicious encoded url detected"
}
deny_reasons[r] if {
  lower(object.get(object.get(input, "tool", {}), "name", "")) == "send_email"
  some u in urls
  object.get(u, "high_entropy_subdomain", false)
  r := "high-entropy subdomain detected"
}
deny_reasons[r] if {
  lower(object.get(object.get(input, "tool", {}), "name", "")) == "send_email"
  some u in urls
  object.get(u, "long_query_string", false)
  r := "dns tunneling / suspicious encoded url detected"
}
deny_reasons[r] if { chunked_exfil; r := "Low-and-slow exfiltration detected by recipient frequency/volume." } # UC29
deny_reasons[r] if { archive_exfil; r := "Archive exfiltration blocked (prohibited contents or encrypted archive to external)." } # UC30
deny_reasons[r] if { direct_blocked_attachment; r := "Attachment blocked: file extension is prohibited by archive_policy.blocked_file_types." } # UC9
deny_reasons[r] if { cloud_forwarding_detected; r := "Cloud forwarding / email-to-storage exfil pattern detected." } # UC31
deny_reasons[r] if { multi_stage_payload; r := "Multi-stage payload delivery suspected (excessive redirects or executable delivery)." } # UC32
deny_reasons[r] if { lolbin_detected; r := "LOLBin / living-off-the-land command pattern detected." } # UC33
deny_reasons[r] if { oauth_phishing; r := "OAuth phishing detected (unapproved client, high-risk scopes, or untrusted redirect)." } # UC34
deny_reasons[r] if { dependency_confusion; r := "Dependency confusion / public-registry install pattern detected." } # UC38
deny_reasons[r] if { confidential_data_found; any_external_domain; r := "Confidential content detected; external sharing is blocked." } # UC8

allow_reasons[r] if {
  r := "Request satisfies role, recipient, domain, and business-hour controls."
}

# QUARANTINE reasons (UC37)
quarantine_reasons[r] if {
  vendor_bec_suspected
  r := "Trusted vendor email shows payment detail mismatch; quarantining for verification."
}

# REQUIRE_APPROVAL reasons (UC22)
approval_reasons[r] if {
  send_as_protected_prefix_requires_approval
  r := "Send-as to protected mailbox requires approval token."
}

approval_reasons[r] if {
  send_as_without_valid_delegation_requires_approval
  r := "Send-as without valid delegation requires approval."
}

# UC10 approval reason is commented out (per request)
# approval_reasons[r] if {
#   needs_approval
#   r := "High-risk send requires approval (C-level recipient off-hours)."
# }

# WARN reasons (UC23)
warn_reasons[r] if {
  language_anomaly
  r := "Language anomaly detected; user confirmation recommended."
}

# THROTTLE reasons (UC3 + UC26)
throttle_reasons[r] if {
  high_urgency_untrusted
  r := sprintf("High urgency score %g (threshold: %g) from untrusted sender; cooling-off period required.", [urgency_score, cfg.urgency_threshold])
}

throttle_reasons[r] if {
  urgency_exploitation
  not has_prompt_injection
  r := "Urgency manipulation signal detected; enforcing cooling-off period."
}

# =========================================================
# Decision selection (priority order)
# =========================================================

decision_outcome = "DENY" if { count(deny_reasons) > 0 }

decision_outcome = "QUARANTINE" if {
  count(deny_reasons) == 0
  count(quarantine_reasons) > 0
}

decision_outcome = "REQUIRE_APPROVAL" if {
  count(deny_reasons) == 0
  count(quarantine_reasons) == 0
  count(approval_reasons) > 0
}

decision_outcome = "THROTTLE" if {
  count(deny_reasons) == 0
  count(quarantine_reasons) == 0
  count(approval_reasons) == 0
  count(throttle_reasons) > 0
}

decision_outcome = "WARN" if {
  count(deny_reasons) == 0
  count(quarantine_reasons) == 0
  count(approval_reasons) == 0
  count(throttle_reasons) == 0
  count(warn_reasons) > 0
}

decision_outcome = "ALLOW" if {
  count(deny_reasons) == 0
  count(quarantine_reasons) == 0
  count(approval_reasons) == 0
  count(throttle_reasons) == 0
  count(warn_reasons) == 0
}

allow if { decision_outcome == "ALLOW" }

# =========================================================
# Reasons aggregation
# =========================================================

reasons := rs if {
  decision_outcome == "DENY"
  rs := sort([r | deny_reasons[r]])
}

reasons := rs if {
  decision_outcome == "QUARANTINE"
  rs := sort([r | quarantine_reasons[r]])
}

reasons := rs if {
  decision_outcome == "REQUIRE_APPROVAL"
  rs := sort([r | approval_reasons[r]])
}

reasons := rs if {
  decision_outcome == "THROTTLE"
  rs := sort([r | throttle_reasons[r]])
}

reasons := rs if {
  decision_outcome == "WARN"
  rs := sort([r | warn_reasons[r]])
}

reasons := rs if {
  decision_outcome == "ALLOW"
  rs := ["Allowed by policy"]
}

reason := reasons[0] if { count(reasons) > 0 }

# =========================================================
# Risk + cooldown
# =========================================================

risk = "high" if { decision_outcome == "DENY" }
risk = "high" if { decision_outcome == "QUARANTINE" }
risk = "medium" if { decision_outcome == "REQUIRE_APPROVAL" }
risk = "medium" if { decision_outcome == "THROTTLE" }
risk = "low" if { decision_outcome == "WARN" }
risk = "low" if { decision_outcome == "ALLOW" }

cooldown_seconds = object.get(cfg, "throttle_seconds", 0) if {
  decision_outcome == "THROTTLE"
}

# =========================================================
# Actions (enforcement hooks)
# =========================================================

actions[a] if {
  decision_outcome == "DENY"
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
  oauth_phishing
  a := "LOCK_ACCOUNT"
}

actions[a] if {
  decision_outcome == "DENY"
  departing_employee_exfil
  a := "MANAGER_LEGAL_REVIEW"
}

actions[a] if {
  decision_outcome == "QUARANTINE"
  a := "QUARANTINE_MESSAGE"
}

actions[a] if {
  decision_outcome == "REQUIRE_APPROVAL"
  a := "REQUEST_APPROVAL"
}

actions[a] if {
  decision_outcome == "WARN"
  a := "REQUEST_USER_CONFIRMATION"
}

actions[a] if {
  decision_outcome == "THROTTLE"
  a := "ENFORCE_COOLDOWN"
}

# =========================================================
# Final decision object
# =========================================================

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

