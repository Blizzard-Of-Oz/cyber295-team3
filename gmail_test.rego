package gmail_test

test_scenario_1_allow_team_email if {
  test_input := {
    "requester": {"identity": "maya@company.com", "role": "soc_analyst"},
    "context": {
      "recipient_count": 2,
      "recipients": ["alice@company.com", "bob@company.com"],
      "recipient_domains": ["company.com"],
      "is_companywide": false,
      "is_working_hours": true,
      "urgency_score": 1,
      "has_prompt_injection": false,
      "attachment_bytes": 0,
      "data_classification": "none",
      "employment_status": "active",
      "record_count": 0
    }
  }

  result := data.gmail.decision with input as test_input
  result.allow
  result.decision == "ALLOW"
}

test_scenario_2_deny_companywide_for_soc if {
  test_input := {
    "requester": {"identity": "maya@company.com", "role": "soc_analyst"},
    "context": {
      "recipient_count": 1,
      "recipients": ["all-employees@company.com"],
      "recipient_domains": ["company.com"],
      "is_companywide": true,
      "is_working_hours": true,
      "urgency_score": 0,
      "has_prompt_injection": false,
      "attachment_bytes": 0,
      "data_classification": "none",
      "employment_status": "active",
      "record_count": 0
    }
  }

  result := data.gmail.decision with input as test_input
  not result.allow
  result.decision == "DENY"
  result.reason == "Insufficient privileges for company-wide email."
}

test_scenario_3_deny_prompt_injection_and_alert if {
  test_input := {
    "requester": {"identity": "maya@company.com", "role": "soc_analyst"},
    "context": {
      "recipient_count": 3,
      "recipients": ["attacker@evil.com", "finance@company.com", "hr@company.com"],
      "recipient_domains": ["evil.com", "company.com"],
      "is_companywide": false,
      "is_working_hours": true,
      "urgency_score": 10,
      "has_prompt_injection": true,
      "attachment_bytes": 0,
      "data_classification": "none",
      "employment_status": "active",
      "record_count": 0
    }
  }

  result := data.gmail.decision with input as test_input
  not result.allow
  result.decision == "DENY"
  "ALERT_SECURITY" in result.actions
  "urgency_throttle_triggered" in result.triggered_controls
  "prompt_injection_detected" in result.triggered_controls
}

test_scenario_4_deny_after_hours_insider_and_lock if {
  test_input := {
    "requester": {"identity": "marcus@company.com", "role": "soc_analyst"},
    "context": {
      "recipient_count": 1,
      "recipients": ["backup@gmail.com"],
      "recipient_domains": ["gmail.com"],
      "is_companywide": false,
      "is_working_hours": false,
      "urgency_score": 0,
      "has_prompt_injection": false,
      "attachment_bytes": 45000000,
      "data_classification": "confidential",
      "employment_status": "notice_period",
      "record_count": 10000
    }
  }

  result := data.gmail.decision with input as test_input
  not result.allow
  result.decision == "DENY"
  "LOCK_ACCOUNT" in result.actions
  "ALERT_SECURITY" in result.actions
}
