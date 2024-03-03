rule win_medusa_bytecodes
{
	meta:
		author = "Matthew @ Embee_Research"
		created = "2023/08/27"
		description = "Medusa Bytecodes"
		sha_256 = "a1211549b4e1a7befd953d03b4d929b3dc9f25ec6c1bc9c05ae92a0ec08fb77c"
		
	strings:
		
		$s1 = {1F ?? 8D ?? ?? ?? 01 25 16 72 ?? ?? ?? 70 A2 25 17 72 ?? ?? ?? 70 28 ?? ?? ?? 0A A2 25 18 20 ?? ?? ?? 00 13 04 12 04 28 ?? ?? ?? 0A A2 25 19 20 ?? ?? ?? 00 13 ?? 12 }
		
		$s2 = "\\Medusa\\obj\\Release\\Medusa.pdb" ascii
		
	condition:
		$s1 or $s2
}