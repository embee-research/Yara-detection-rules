rule win_lumma_simple_strings
{
	meta:
		author = "Matthew @ Embee_Research"
		created = "2023/09/13"
		description = ""
		sha_256 = "277d7f450268aeb4e7fe942f70a9df63aa429d703e9400370f0621a438e918bf"
		
	strings:
		
		$s1 = "Binedx765ance Chaedx765in Waledx765let" wide
		$s2 = "%appdaedx765ta%\\Moedx765zilla\\Firedx765efox\\Profedx765iles"
		$s3 = "\\Locedx765al Extensedx765ion Settinedx765gs\\" 
		$s4 = "%appdedx765ata%\\Opedx765era Softwedx765are\\Opedx765era GX Staedx765ble"


		/*
			Wedx765eb Daedx765ta
			Opedx765era Neoedx765n
			Loedx765gin Daedx765ta

		*/

		$o1 = {57 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 65 00 62 00 20 00 44 00 61 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 74 00 61 00}
		$o2 = {4f 00 70 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 65 00 72 00 61 00 20 00 4e 00 65 00 6f 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 6e 00}
		$o3 = {4c 00 6f 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 67 00 69 00 6e 00 20 00 44 00 61 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 74 00 61 00}

	condition:
		uint16(0) == 0x5a4d
		and
		filesize < 5000KB
		and
		(
			(all of ($s*))
			or
			(all of ($o*))
		)


}