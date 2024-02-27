rule Ransom_Note {
	meta:
		author = "ian engelbrecht"
		description = "Ransom Note"
	strings:
		$string = "/\\b([a-z2-7]{56}.onion)\\b/i"
		$string = "pay the money"
		$string = "pay the ransom"
		$string = "pay for decryption"
	condition:
		1 of them
}