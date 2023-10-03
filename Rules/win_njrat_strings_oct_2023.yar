import "dotnet"

rule win_njrat_strings_oct_2023
{
	meta:
		author = "Matthew @ Embee_Research"
		created = "2023/10/03"
		description = ""
		sha_256 = "59d6e2958780d15131c102a93fefce6e388e81da7dc78d9c230aeb6cab7e3474"
		
	strings:
		$s1 = "netsh firewall delete allowedprogram" wide
		$s2 = "cmd.exe /c ping 0 -n 2 & del" wide
		$s3 = "netsh firewall add allowedprogram" wide
		$s4 = "Execute ERROR" wide
		$s5 = "Update ERROR" wide
		$s6 = "Download ERROR" wide
		
	condition:
			dotnet.is_dotnet
		and
			(all of ($s*))
		

}