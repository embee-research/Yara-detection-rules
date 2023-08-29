
rule win_remcos_rat_unpacked
{
	meta:
		author = "Matthew @ Embee_Research"
		created = "2023/08/27"
		description = "Detects strings present in remcos rat Samples."
		sha_256 = "ec901217558e77f2f449031a6a1190b1e99b30fa1bb8d8dabc3a99bc69833784"
		
	strings:
		$r0 = " ______                              " ascii
		$r1 = "(_____ \\                             " ascii
		$r2 = " _____) )_____ ____   ____ ___   ___ " ascii 
		$r3 = "|  __  /| ___ |    \\ / ___) _ \\ /___)" ascii
		$r4 = "| |  \\ \\| ____| | | ( (__| |_| |___ |" ascii
		$r5 = "|_|   |_|_____)_|_|_|\\____)___/(___/ " ascii
		
		$s1 = "Watchdog module activated" ascii
		$s2 = "Remcos restarted by watchdog!" ascii
		$s3 = " BreakingSecurity.net" ascii

	condition:
		//uint16(0) == 0x5a4d 
		//and
		(
			(all of ($r*)) or (all of ($s*))
		)
	
	
		

}