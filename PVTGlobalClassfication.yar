include "C:\Yara\PVTGenericUserDataPatterns.yar"
include "C:\Yara\PVTTestCreditCardNumbers.yar"

rule CombinedRules {
  meta:
    description = "Master Rule Combining GenericUserDataPatterns and TestCreditCardNumbers"
  condition:
    GenericUserDataPatterns and TestCreditCardNumbers
}
