package gmail

default allow = false

denied_recipients := {"yaoyaozong@gmail.com"}

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
	input.context.urgency_manipulation == true
	reason := "urgency manipulation detected"
}

allow {
	count(deny) == 0
}

decision = {
	"allow": allow,
	"reason": reason,
}

reason = "ok" {
	allow
}

reason = r {
	not allow
	deny[r]
}
