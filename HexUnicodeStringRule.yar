rule HexUnicodeStringRule {
  strings:
    $hex_unicode_string = { 48 00 69 00 74 00 20 00 61 00 6E 00 79 00 20 00 6B 00 65 00 79 00 20 00 74 00 6F 00 20 00 65 00 78 00 69 00 74 00 2E 00 }
  condition:
    $hex_unicode_string
}
