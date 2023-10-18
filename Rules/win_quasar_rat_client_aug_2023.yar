import "dotnet"

rule win_quasar_rat_client
{
	meta:
		author = "Matthew @ Embee_Research"
		created = "2023/08/27"
		description = "Detects strings present in Quasar Rat Samples."
		sha_256 = "914d88f295ac2213f37d3f71e6d4383979283d1728079a208f286effb44d840c"
		sha_256 = "45a724179ae1d08044c4bafb69c7f9cdb4ed35891dc9cf24aa664d75464ceb6d"
		sha_256 = "7e13bcd73232c3f33410aa95f61e1196a2f9ae35e05c1f9c8f251e07077a9dfb"
		
	strings:
	
		$s1 = "Quasar Client" ascii wide
		$s2 = "Quasar.Client.Properties.Resources" ascii wide
		$s3 = "Google\\Chrome\\User Data\\Default\\" wide
		$s4 = "\\Mozilla\\Firefox\\Profiles" wide
		$s5 = "Yandex\\YandexBrowser\\User Data\\Default\\" wide
		
	condition:
			uint16(0) == 0x5a4d 
		and
			dotnet.is_dotnet 
		and
			filesize < 7000KB 
		and 
			( 
				for any i in (0..dotnet.number_of_resources-1):
					(dotnet.resources[i].name == "Quasar.Client*")
			or
				(3 of ($s*))
			)
		
		

}