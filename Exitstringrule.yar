rule ExitStringRule {
  strings:
    $exit_string = "Hit any key to exit..." wide
  condition:
    $exit_string
}
