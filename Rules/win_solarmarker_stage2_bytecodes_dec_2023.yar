rule win_solarmarker_stage2_bytecodes_dec_2023
{
	meta:
		author = "Matthew @ Embee_Research"
		created = "2023/12/28"
		description = "Patterns observed in Solarmarker stage2 dll"
		sha_256 = "4a3b60496a793ee96a51fecf8690ef8312429a6b54d32f2a4424395c47b47fc8"
		sha_256 = "e0b2457491a8c2d50710aa343ad1957a76f83ceaf680165ffa0e287fe18abbd6"
		
	strings:
	
		$s1 = {6F ?? ?? 00 0A 1F 20 2E ?? 02 7B ?? ?? 00 04 02 7B ?? ?? 00 04 6F ?? ?? 00 0A 1F 09 2E ?? 02 7B ?? ?? 00 04 02 7B ?? ?? 00 04 6F ?? ?? 00 0A 1F 0A 2E ?? 02 7B ?? ?? 00 04 02 7B ?? ?? 00 04 6F ?? ?? 00 0A 1F 0D 2E ?? 02 7B ?? ?? 00 04 02 7B ?? ?? 00 04 6F ?? ?? 00 0A 1F 0A }
		
	
	
	condition:
		$s1
		

}

