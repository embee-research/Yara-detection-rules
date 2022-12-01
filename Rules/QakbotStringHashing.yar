
rule qakbot_api_hashing
{
	meta:
		author = "@Embee_Research"
		vendor = "Huntress Labs"
		created = "2022/11/14"
		updated = "2022/12/01"
		reference =  "@Embee_Research @HuntressLabs"
		reference = "https://twitter.com/embee_research/status/1592067841154756610"
	strings:
		
		//Qakbot string hashing routine extracted from Ghidra
		//This is unique to qakbot samples
		$qakbot_hashing = {0f b6 04 39 33 f0 8b c6 c1 ee 04 83 e0 0f 33 34 85 ?? ?? ?? ?? 8b c6 c1 ee 04 83 e0 0f 33 34 85 ?? ?? ?? ?? 41 3b ca} 

		//Optional component (unique-ish crc32 block), has some false positives. 
		//Uncomment to re-enable
		//$qakbot_crc32_stringblock = {00 00 00 00 64 10 b7 1d c8 20 6e 3b ac 30 d9 26 90 41 dc 76 f4 51 6b 6b 58 61 b2 4d 3c 71 05 50 20 83 b8 ed 44 93 0f f0 e8 a3 d6 d6 8c b3 61 cb b0 c2 64 9b d4 d2 d3 86 78 e2 0a a0 1c f2 bd bd}
		
	condition:
		any of them
		//add "and uint16(0) == 0x5a4d" for better performance but less accuracy
}
