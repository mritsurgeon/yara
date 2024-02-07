rule HexUnicode_TextStringRule {
  meta:
    author = "Ian Engelbrecht"
    description = "Detects a specific Unicode text string and a hex value for that string"
  strings:
    $hex_unicode_string = { 48 00 69 00 74 00 20 00 61 00 6E 00 79 00 20 00 6B 00 65 00 79 00 20 00 74 00 6F 00 20 00 65 00 78 00 69 00 74 00 2E 00 }
    $exit_string = "Hit any key to exit..." wide
  condition:
    $hex_unicode_string or $exit_string
}


