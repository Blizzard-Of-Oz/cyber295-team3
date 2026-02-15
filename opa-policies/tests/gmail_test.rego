package gmail_test

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

test_allow_internal_team_email {
  data.gmail.allow with input as base_input
}

test_deny_blocked_specific_recipient {
  input := object.union(base_input, {
    "tool": {
      "name": "send_email",
      "arguments": {
        "to": ["yaoyaozong@gmail.com"],
        "subject": "Hi",
        "body": "blocked"
      }
    }
  })

  not data.gmail.allow with input as input
  contains(data.gmail.decision.reason with input as input, "blocked_recipient:")
}

test_deny_external_recipient_not_allowed {
  input := object.union(base_input, {
    "tool": {
      "name": "send_email",
      "arguments": {
        "to": ["random.external@example.com"],
        "subject": "Hi",
        "body": "external"
      }
    }
  })

  not data.gmail.allow with input as input
  contains(data.gmail.decision.reason with input as input, "external_recipient_not_allowed:")
}

test_allow_whitelisted_external_email {
  input := object.union(base_input, {
    "tool": {
      "name": "send_email",
      "arguments": {
        "to": ["team3.mcp@gmail.com"],
        "subject": "Hi",
        "body": "allowed"
      }
    }
  })

  data.gmail.allow with input as input
}

test_deny_broadcast_for_non_privileged_requester {
  input := {
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

  not data.gmail.allow with input as input
  contains(data.gmail.decision.reason with input as input, "broadcast_requires_privileged_identity:")
}

test_allow_broadcast_for_privileged_requester {
  input := {
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

  data.gmail.allow with input as input
}

test_deny_bulk_recipients_over_limit {
  input := object.union(base_input, {
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

  not data.gmail.allow with input as input
  contains(data.gmail.decision.reason with input as input, "max_recipients_exceeded:")
}

test_deny_empty_subject_when_required {
  input := object.union(base_input, {
    "tool": {
      "name": "send_email",
      "arguments": {
        "to": ["alice@ischool.berkeley.edu"],
        "subject": "",
        "body": "no subject"
      }
    }
  })

  not data.gmail.allow with input as input
  data.gmail.decision.reason with input as input == "subject_required"
}

test_non_send_action_is_not_blocked {
  input := {
    "tool": {
      "name": "get_email",
      "arguments": {
        "messageId": "123"
      }
    }
  }

  data.gmail.allow with input as input
}
