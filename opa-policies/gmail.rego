package gmail

default allow := false

denied_recipients := {"yaoyaozong@gmail.com"}

recipients[addr] if {
	type_name(input.tool.arguments.to) == "array"
	addr := input.tool.arguments.to[_]
}

recipients[addr] if {
	type_name(input.tool.arguments.to) == "string"
	addr := input.tool.arguments.to
}

recipients[addr] if {
	type_name(input.tool.arguments.cc) == "array"
	addr := input.tool.arguments.cc[_]
}

recipients[addr] if {
	type_name(input.tool.arguments.cc) == "string"
	addr := input.tool.arguments.cc
}

recipients[addr] if {
	type_name(input.tool.arguments.bcc) == "array"
	addr := input.tool.arguments.bcc[_]
}

recipients[addr] if {
	type_name(input.tool.arguments.bcc) == "string"
	addr := input.tool.arguments.bcc
}

recipients[addr] if {
	type_name(input.tool.arguments.message.to) == "array"
	addr := input.tool.arguments.message.to[_]
}

recipients[addr] if {
	type_name(input.tool.arguments.message.to) == "string"
	addr := input.tool.arguments.message.to
}

deny[reason] if {
	recipients[recipient]
	denied_recipients[blocked]
	lower(recipient) == lower(blocked)
	reason := sprintf("recipient %s is blocked", [blocked])
}

deny[reason] if {
	input.tool.name == "send_email"
	input.context.urgency_manipulation == true
	reason := "urgency manipulation detected"
}

deny[reason] if {
	input.tool.name == "send_email"
	some url in object.get(input.context, "urls", [])
	object.get(url, "suspicious_query_payload", false) == true
	reason := "suspicious encoded url payload detected"
}

deny[reason] if {
	input.tool.name == "send_email"
	object.get(input.context, "dns_tunneling_detected", false) == true
	some url in object.get(input.context, "urls", [])
	object.get(url, "suspicious_domain_pattern", false) == true
	reason := "dns tunneling / suspicious c2 domain detected"
}

deny[reason] if {
	input.tool.name == "send_email"
	some url in object.get(input.context, "urls", [])
	object.get(url, "suspicious_hostname_pattern", false) == true
	reason := "suspicious exfiltration domain detected"
}

deny[reason] if {
	input.tool.name == "send_email"
	some url in object.get(input.context, "urls", [])
	object.get(url, "looks_base64_subdomain", false) == true
	reason := "dns tunneling / suspicious encoded url detected"
}

deny[reason] if {
	input.tool.name == "send_email"
	some url in object.get(input.context, "urls", [])
	object.get(url, "high_entropy_subdomain", false) == true
	reason := "high-entropy subdomain detected"
}

deny[reason] if {
	input.tool.name == "send_email"
	some url in object.get(input.context, "urls", [])
	object.get(url, "long_query_string", false) == true
	reason := "dns tunneling / suspicious encoded url detected"
}

allow if {
	count(deny) == 0
}

reason := "ok" if {
	allow
}

reason := r if {
        not allow
        reasons := sort([d | deny[d]])
        count(reasons) > 0
        r := reasons[0]
}

decision := {
	"allow": allow,
	"reason": reason,
} if {
	true
}
