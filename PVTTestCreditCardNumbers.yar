private rule TestCreditCardNumbers {
  meta:
    author = "Ian engelbrecht"
    description = "Detects test credit card account numbers"
	strings:
		$amex4 = /\b37\d{13}\b/
		$mastercard = /\b5[1-5]\d{14}\b/
		$visa = /\b(4\d{12}(\d{3}))\b/
		$dinersclub = /\b(3(0[0-5]|[68][0-9])\d{11})\b/
		$discover = /\b((6011\d{12}|65\d{14}))\b/
		$jcb = /\b((35\d{14}|2131\d{11}|1800\d{11}))\b/
	condition:
		1 of them

}
