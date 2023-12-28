rule win_redline_loader_dec_2023
{
	meta:
		author = "Matthew @ Embee_Research"
		created = "2023/12/24"
		description = "Patterns observed in redline loader"
		sha_256 = ""
		
	strings:
	
		$s1 = {8b ?? ?? 0c 30 04 31 46 3b f7 7c ?? 5d 5b 5e 83 ?? ?? 75}
		$s2 = "WritePrivateProfileStringA"
		$s3 = "SetFileShortNameA"
		$s4 = "- Attempt to use MSIL code from this assembly during native code initialization"
	
	condition:
		all of them
		

}

