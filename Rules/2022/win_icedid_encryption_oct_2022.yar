rule win_icedid_encryption_oct_2022
{
	//Detects IcedID Encryption Routine present in unpacked payloads
	//If infected, unpacked payload should be running in memory and available via yara scan.
	meta:
		author = "Embee_Research @ Huntress"
		created = "2022/10/14"
	strings:
		
		//IcedID Encryption Routine extracted from Ghidra
		//This is likely to change in future but works well on most recent variants. 
		$IcedID = {41 0f b6 d3 44 8d 42 01 83 e2 03 41 83 e0 03 42 8a 44 84 40 02 44 94 40 43 32 04 33 42 8b 4c 84 40 41 88 04 1b 83 e1 07 8b 44 94 40 49 ff c3 d3 c8 ff c0 89 44 94 40 83 e0 07} 
	
		
	condition:
		$IcedID
		//add "and uint16(0) == 0x5a4d" for better performance but less accuracy
}