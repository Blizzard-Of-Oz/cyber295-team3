package gmail_test

import future.keywords

base_input := {
  "tool": {
    "name": "send_email",
    "arguments": {
      "to": ["alice@ischool.berkeley.edu"],
      "subject": "Weekly update",
      "body": "All good"
    }
  },
  "requester": {
    "identity": "analyst@ischool.berkeley.edu"
  },
  "request": {
    "headers": {
      "x-authenticated-user": "analyst@ischool.berkeley.edu"
    }
  }
}

test_allow_internal_team_email if {
  data.gmail.allow with input as base_input
}

test_deny_blocked_specific_recipient if {
  inp := object.union(base_input, {
    "tool": {
      "name": "send_email",
      "arguments": {
        "to": ["yaoyaozong@gmail.com"],
        "subject": "Hi",
        "body": "blocked"
      }
    }
  })

  not data.gmail.allow with input as inp

  r := data.gmail.decision.reason with input as inp
  contains(r, "blocked_recipient:")
}

test_deny_external_recipient_not_allowed if {
  inp := object.union(base_input, {
    "tool": {
      "name": "send_email",
      "arguments": {
        "to": ["random.external@example.com"],
        "subject": "Hi",
        "body": "external"
      }
    }
  })

  not data.gmail.allow with input as inp

  r := data.gmail.decision.reason with input as inp
  contains(r, "external_recipient_not_allowed:")
}

test_allow_whitelisted_external_email if {
  inp := object.union(base_input, {
    "tool": {
      "name": "send_email",
      "arguments": {
        "to": ["team3.mcp@gmail.com"],
        "subject": "Hi",
        "body": "allowed"
      }
    }
  })

  data.gmail.allow with input as inp
}

test_deny_broadcast_for_non_privileged_requester if {
  inp := {
    "tool": {
      "name": "send_email",
      "arguments": {
        "to": ["all@ischool.berkeley.edu"],
        "subject": "Broadcast",
        "body": "Notice"
      }
    },
    "requester": {
      "identity": "analyst@ischool.berkeley.edu"
    },
    "request": {
      "headers": {
        "x-authenticated-user": "analyst@ischool.berkeley.edu"
      }
    }
  }

  not data.gmail.allow with input as inp

  r := data.gmail.decision.reason with input as inp
  contains(r, "broadcast_requires_privileged_identity:")
}

test_allow_broadcast_for_privileged_requester if {
  inp := {
    "request": {
      "body": {
        "name": "send_email",
        "arguments": {
          "to": ["all@ischool.berkeley.edu"],
          "subject": "Broadcast",
          "body": "Notice"
        }
      },
      "headers": {
        "x-authenticated-user": "team3@billyyaoischoolberkeley.onmicrosoft.com"
      }
    }
  }

  data.gmail.allow with input as inp
}

test_deny_bulk_recipients_over_limit if {
  inp := object.union(base_input, {
    "tool": {
      "name": "send_email",
      "arguments": {
        "to": [
          "u1@ischool.berkeley.edu",
          "u2@ischool.berkeley.edu",
          "u3@ischool.berkeley.edu",
          "u4@ischool.berkeley.edu",
          "u5@ischool.berkeley.edu",
          "u6@ischool.berkeley.edu",
          "u7@ischool.berkeley.edu",
          "u8@ischool.berkeley.edu",
          "u9@ischool.berkeley.edu",
          "u10@ischool.berkeley.edu",
          "u11@ischool.berkeley.edu"
        ],
        "subject": "bulk",
        "body": "bulk body"
      }
    }
  })

  not data.gmail.allow with input as inp

  r := data.gmail.decision.reason with input as inp
  contains(r, "max_recipients_exceeded:")
}

test_deny_empty_subject_when_required if {
  inp := object.union(base_input, {
    "tool": {
      "name": "send_email",
      "arguments": {
        "to": ["alice@ischool.berkeley.edu"],
        "subject": "",
        "body": "no subject"
      }
    }
  })

  not data.gmail.allow with input as inp

  r := data.gmail.decision.reason with input as inp
  r == "subject_required"
}

test_non_send_action_is_not_blocked if {
  inp := {
    "tool": {
      "name": "get_email",
      "arguments": {
        "messageId": "123"
      }
    }
  }

  data.gmail.allow with input as inp
}
