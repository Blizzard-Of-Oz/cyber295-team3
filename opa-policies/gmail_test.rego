package gmail

test_uc29_allows_below_threshold {
  result := data.gmail.decision with input as {
    "tool": {"name": "send_email", "arguments": {"to": "personal@gmail.com"}},
    "context": {
      "counters": {
        "recipient": "personal@gmail.com",
        "emails_to_same_recipient_last_24h": 2,
        "emails_to_same_recipient_last_1h": 1,
        "uc29_thresholds": {"emails_last_24h": 4, "emails_last_1h": 3}
      }
    }
  }

  result.allow == true
}

test_uc29_denies_after_threshold_crossed {
  result := data.gmail.decision with input as {
    "tool": {"name": "send_email", "arguments": {"to": "personal@gmail.com"}},
    "context": {
      "counters": {
        "recipient": "personal@gmail.com",
        "emails_to_same_recipient_last_24h": 4,
        "emails_to_same_recipient_last_1h": 2,
        "uc29_thresholds": {"emails_last_24h": 4, "emails_last_1h": 3}
      }
    }
  }

  result.allow == false
  contains(lower(result.reason), "uc29")
  result.triggered_controls[_] == "chunked_exfil_detected"
}

test_uc26_blocked_recipient_still_denied {
  result := data.gmail.decision with input as {
    "tool": {"name": "send_email", "arguments": {"to": "yaoyaozong@gmail.com"}},
    "context": {"counters": {}}
  }

  result.allow == false
  contains(lower(result.reason), "blocked")
}
