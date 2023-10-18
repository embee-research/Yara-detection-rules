rule win_emotet_string_patterns_oct_2022

{
	meta:
		author = "Embee_Research @ HuntressLabs"
		created = "2022/10/14"
		description = "Detection of string hashing routines observed in emotet"
	strings:
		
		$em1 = {45 33 f6 4c 8b d0 48 85 c0 74 64 48 8d 14 b3 4c 8b c0 45 8b de 4c 8b ca 4c 2b cb 49 83 c1 03 49 c1 e9 02 48 3b da 4d 0f 47 ce}
		$em2 = {8b cd 49 ff c3 33 0b 48 8d 5b 04 0f b6 c1 66 41 89 00 0f b7 c1 c1 e9 10 66 c1 e8 08 4d 8d 40 08 66 41 89 40 fa 0f b6 c1 66 c1 e9 08 66 41 89 40 fc 66 41 89 48 fe 4d 3b d9}
		$em3 = {49 ff c3 33 0b 48 8d 5b 04 0f b6 c1 66 41 89 00}		
		$em4 = {8b cb 41 8b d0 d3 e2 41 8b cb d3 e0 03 d0 41 0f be c1 03 d0 41 2b d0 49 ff c2 44 8b c2}
		
		
	condition:
		uint16(0) == 0x5a4d and
		(any of them)
}