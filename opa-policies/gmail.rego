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
} if {
	true
}