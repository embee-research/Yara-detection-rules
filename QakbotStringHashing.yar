
rule qakbot_api_hashing
{
	meta:
		author = "Embee_Research @ Huntress"
		created = "2022/11/14"
		//Twitter @Embee_Reseach @HuntressLabs
	strings:
		
		//Qakbot string hashing routine extracted from Ghidra
		$qakbot_hashing = {0f b6 04 39 33 f0 8b c6 c1 ee 04 83 e0 0f 33 34 85 ?? ?? ?? ?? 8b c6 c1 ee 04 83 e0 0f 33 34 85 ?? ?? ?? ?? 41 3b ca} 
	
		
	condition:
		$qakbot_hashing
		//add "and uint16(0) == 0x5a4d" for better performance but less accuracy
}