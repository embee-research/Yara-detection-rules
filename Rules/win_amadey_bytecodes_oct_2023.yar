
rule win_amadey_bytecodes_oct_2023
{
	meta:
		author = "Matthew @ Embee_Research"
		created = "2023/10/15"
		description = "Detects bytecodes present in Amadey Bot malware"
		sha256 = "4165190e60ad5abd437c7768174b12748d391b8b97c874b5bdf8d025c5e17f43"
		
	strings:
		$s1 = {8b ?? fc 83 c1 23 2b c2 83 c0 fc 83 f8 1f 77}
		$s2 = {80 ?? ?? ?? 3d 75 }
		$s3 = {8b c1 c1 f8 10 88 ?? ?? 8b c1 c1 f8 08}
		
	condition:
		
		$s1 and $s2 and $s3
		

}