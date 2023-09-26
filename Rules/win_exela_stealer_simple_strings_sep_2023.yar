
import "dotnet"

rule win_exela_stealer_simple_strings_sep_2023
{ 
	meta:
		author = "Matthew @embee_research"
		date = "2023/09/24"
		sha256 = "bf5d70ca2faf355d86f4b40b58032f21e99c3944b1c5e199b9bb728258a95c1b"
	strings:
        $s1 = "https://i.instagram.com/api/v1/accounts/current_user/" wide
        $s2 = "/create /f /sc onlogon /rl highest /tn \"AutoUpdateCheckerOnLogon\" /tr " wide
		$s4 = "https://discord.com/api/webhooks/" wide
		$s5 = "Browser : {0} | Name : {1} | Value : {2} | Date created (timestamp) : {3} |  Date last used (timestamp) : {4} | Count {5}" wide
		$s6 = "Browser : {0} | {1} {2}/{3} {4}" wide
	
	
		$e1 = "Exela.Program" wide ascii
		$e2 = "Exela.Wifi" wide ascii
		$e3 = "Exela.Components" wide ascii
		$e4 = "Exela Stealer" wide ascii
		$e5 = "Exela.exe" wide ascii
	
	condition:
		dotnet.is_dotnet
		and
		(
			(all of ($s*))
			or 
			(3 of ($e*))
		)
}
