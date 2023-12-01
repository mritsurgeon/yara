rule GenericUserDataPatterns {
  meta:
    author = "Ian Engelbrecht"
    description = "Detects generic patterns for email, phone number, and SSN"
  strings:
    $email_pattern = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/
    $phone_pattern = /\b\d{3}-\d{3}-\d{4}\b/
    $ssn_pattern = /\b\d{3}-\d{2}-\d{4}\b/
  condition:
    all of ($email_pattern, $phone_pattern, $ssn_pattern)
}
