private rule GenericUserDataPatterns {
  meta:
    author = "Ian Engelbrecht"
    description = "Detects generic patterns for email, phone number, and SSN"
  strings:
    $email_pattern = /[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}/
    $phone_pattern = /\b\d{3}-\d{3}-\d{4}\b/
    $ssn_pattern = /\b\d{3}-\d{2}-\d{4}\b/
  condition:
    1 of ($email_pattern, $phone_pattern, $ssn_pattern)
}
