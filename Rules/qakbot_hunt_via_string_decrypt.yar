rule qakbot_string_decrypt
{
	meta:
		author = "Embee_Research @ Huntress"
		created = "2022/11/14"
	strings:
		
		//Qakbot string hashing routine extracted from Ghidra
		$qakbot_decrypt = {33 d2 8b c7 f7 75 10 8a 04 1a 8b 55 fc 32 04 17 88 04 39 47 83 ee 01} 
	
		
	condition:
		$qakbot_decrypt
		//add "and uint16(0) == 0x5a4d" for better performance but less accuracy
}