
import "dotnet"


rule win_njrat_bytecodes_V2_oct_2023
{
	meta:
		author = "Matthew @ Embee_Research"
		created = "2023/10/03"
		description = ""
		sha_256 = "9877fc613035d533feda6adc6848e183bf8c8660de3a34b1acd73c75e62e2823"
		sha_256 = "40f07bdfb74e61fe7d7973bcd4167ffefcff2f8ba2ed6f82e9fcb5a295aaf113"
		
	strings:
		$s1 = {03 1F 72 2E ?? 03 1F 73 2E ?? 03 1F 74 2E ?? 03 1F 75 2E ?? 03 1F 76 2E ?? }
		$s2 = {0B 14 0C 16 0D 16 13 ?? 16 13 ?? 14}
		

	condition:
		dotnet.is_dotnet
		
		and
	
		(all of ($s*))
		

}