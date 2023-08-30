import "dotnet"

rule win_xworm_simple_strings
{
	meta:
		author = "Matthew @ Embee_Research"
		created = "2023/08/30"
		description = "Detects simple strings present in unobfuscated xworm"
		sha_256 = "4459d95c0493d640ecc9453cf6a4f2b7538b1a7b95032f70803fc726b8e40422"
		sha_256 = "820bb1a31f421b90ea51efc3e71cc720c8c2784fb1e882e732e8fafb8631a389"
		
	strings: 
	
		$x1 = "XWorm V" wide nocase
	
		$s1 = "/create /f /RL HIGHEST /sc minute /mo 1 /tn " wide
		$s2 = "/create /f /sc minute /mo 1 /tn " wide
		$s3 = "-ExecutionPolicy Bypass Add-MpPreference -ExclusionPath " wide
		
	condition:
			dotnet.is_dotnet 
		and
			$x1
		and
			(2 of ($s*))
		
		

}