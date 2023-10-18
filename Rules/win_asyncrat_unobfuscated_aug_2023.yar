import "dotnet"

rule win_asyncrat_unobfuscated
{
	meta:
		author = "Matthew @ Embee_Research"
		created = "2023/08/27"
		description = "Detects strings present in unobfuscated AsyncRat Samples. Rule may also pick up on other Asyncrat-derived malware (Dcrat/venom etc)"
		sha_256 = "db84db8c5d76f6001d5503e8e4b16cdd3446d5535c45bbb0fca76cfec40f37cc"
		
	condition:
			dotnet.is_dotnet 
		and
			filesize < 7000KB 
		and 
			( 
				for any class in dotnet.classes: ( class.namespace == "Client.Algorithm")
				and
				for any class in dotnet.classes: ( class.namespace == "Client.Connection")
				and
				for any class in dotnet.classes: ( class.namespace == "Client.Helper")
				and
				for any class in dotnet.classes: ( class.namespace == "Client.Install")
			
			)
		
		

}