rule PII_detector
{
    strings:
	$s0 = "c0107a2664cee88d3f906f97ec162ed6" fullword // weight: 1.756
	$s1 = "85acf301f88a33860800e1a60db015cd" fullword // weight: 1.74
	$s2 = "7aebd73866b61bd44de11df73785c703" fullword // weight: 1.737
	$s3 = "e7f46cb69985041177dff179db0e5b3f" fullword // weight: 1.721
	$s4 = "6b2f9082fa1bc48a328c1a03754da1ea" fullword // weight: 1.719
	$s5 = "ebcab1a509441fd2c87e456f7bf094af" fullword // weight: 1.705
	$s6 = "2239c04d6dfd37a5e03ed367bafde7b0" fullword // weight: 1.705
	$s7 = "daa06ab85031cf1145859bb20d488b98" fullword // weight: 1.483
	$s8 = "81f8a8ebf1a0b08f11bb2366918814fa" fullword // weight: 1.476
	$s9 = "e7722ebf9901cb787bf411108212c9e2" fullword // weight: 1.454
	$s10 = "8f676c7c6c1bf779447564f682374ad8" fullword // weight: 1.439
	$s11 = "82129b156486c77aae506cbc2d61ba3e" fullword // weight: 1.11
	$s12 = "8080fc10ab270366dacd92d9660842d2" fullword // weight: 1.09
	$s13 = "filesize"           fullword // weight: -0.002109

    condition:
	((#s0 * 1.756) + (#s1 * 1.740) + (#s2 * 1.737) + (#s3 * 1.721) + (#s4 * 1.719) + (#s5 * 1.705) + (#s6 * 1.705) + (#s7 * 1.483) + (#s8 * 1.476) + (#s9 * 1.454) + (#s10 * 1.439) + (#s11 * 1.110) + (#s12 * 1.090) + (#s13 * -0.002) + (1.704)) > 0

}
