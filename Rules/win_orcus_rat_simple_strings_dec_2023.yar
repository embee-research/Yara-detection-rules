rule win_orcus_rat_simple_strings_dec_2023
{
	meta:
		author = "Matthew @ Embee_Research"
		created = "2023/12/24"
		description = "Strings observed in Orcus RAT"
		sha_256 = "30a2a674d55d7898d304713dd2f69a043d875230ea7ebee22596ba4c640768db"
		
	strings:
	
		$s1 = "Orcus is a Remote Administration Tool for Windows. It allows the administrator to make changes to the system remotely." wide
		$s2 = "Orcus.Service" wide
		$s4 = "costura.orcus" wide
		$s5 = "Orcus.Commands"
		$s6 = "Orcus.Shared"
		$s7 = "Orcus.Utilities"
		$s8 = "Orcus.StaticCommands"
		$s9 = "Orcus.Plugins"
		
	
	
	condition:
		(5 of them)
		

}

