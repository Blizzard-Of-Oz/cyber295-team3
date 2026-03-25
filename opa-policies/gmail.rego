package gmail

default allow = false

denied_recipients := {"yaoyaozong@gmail.com"}
counters := object.get(object.get(input, "context", {}), "counters", {})
thresholds := object.get(counters, "uc29_thresholds", {})
uc29_email_threshold_24h := object.get(thresholds, "emails_last_24h", 4)
uc29_email_threshold_1h := object.get(thresholds, "emails_last_1h", 3)

recipients[addr] {
	type_name(input.tool.arguments.to) == "array"
	addr := input.tool.arguments.to[_]
}

recipients[addr] {
	type_name(input.tool.arguments.to) == "string"
	addr := input.tool.arguments.to
}

recipients[addr] {
	type_name(input.tool.arguments.cc) == "array"
	addr := input.tool.arguments.cc[_]
}

recipients[addr] {
	type_name(input.tool.arguments.cc) == "string"
	addr := input.tool.arguments.cc
}

recipients[addr] {
	type_name(input.tool.arguments.bcc) == "array"
	addr := input.tool.arguments.bcc[_]
}

recipients[addr] {
	type_name(input.tool.arguments.bcc) == "string"
	addr := input.tool.arguments.bcc
}

recipients[addr] {
	type_name(input.tool.arguments.message.to) == "array"
	addr := input.tool.arguments.message.to[_]
}

recipients[addr] {
	type_name(input.tool.arguments.message.to) == "string"
	addr := input.tool.arguments.message.to
}

deny[reason] {
	recipients[recipient]
	denied_recipients[blocked]
	lower(recipient) == lower(blocked)
	reason := sprintf("recipient %s is blocked", [blocked])
}

deny[reason] {
	input.tool.name == "send_email"
	emails24h := object.get(counters, "emails_to_same_recipient_last_24h", 0)
	emails1h := object.get(counters, "emails_to_same_recipient_last_1h", 0)
	recipient := object.get(counters, "recipient", "unknown")
	emails24h >= uc29_email_threshold_24h
	reason := sprintf("UC29 chunked exfiltration detected for %s: repeated low-and-slow sends in 24h window", [recipient])
}

deny[reason] {
	input.tool.name == "send_email"
	emails1h := object.get(counters, "emails_to_same_recipient_last_1h", 0)
	recipient := object.get(counters, "recipient", "unknown")
	emails1h >= uc29_email_threshold_1h
	reason := sprintf("UC29 low-and-slow exfiltration pattern detected for %s: repeated sends in 1h window", [recipient])
}

allow {
	count(deny) == 0
}

decision = {
	"allow": allow,
	"actions": [],
	"cooldown_seconds": 0,
	"decision": decision_label,
	"policy_version": "v3",
	"reason": reason,
	"reasons": reasons,
	"risk": risk,
	"triggered_controls": triggered_controls,
}

decision_label = "ALLOW" {
	allow
}

decision_label = "DENY" {
	not allow
}

reason = "ok" {
	allow
}

reason = r {
	not allow
	deny[r]
}

reasons := ["Allowed by policy"] {
	allow
}

reasons := rs {
	not allow
	rs := [r | deny[r]]
}

risk = "low" {
	allow
}

risk = "high" {
	not allow
}

triggered_controls := [] {
	allow
}

triggered_controls := ["chunked_exfil_detected"] {
	not allow
	some r
	deny[r]
	contains(lower(r), "uc29")
}
