
import "dotnet"

rule win_agent_tesla_bytecodes_sep_2023
{ 
	meta:
		author = "Matthew @embee_research"
		date = "2023/09/21"
		sha256 = "ce696cf7a6111f5e7c6781854de04ddc262b6c9b39c059fd5435dfb3b8901f04"
		sha256 = "afc29232c4989587db2c54b7c9f145fd0d73537e045ece15338582ede5389fce"
		sha256 = "fba4374163ba25c9dc572f1a5d7f3e46e09531ab964d808f3dde2a19c05a2ee5"
	strings:
		
		$s1 = {8F ?? ?? ?? ?? 25 47 FE ?? ?? ?? FE ?? ?? ?? 91 61 D2 52 20 ?? ?? ?? ?? FE ?? ?? ?? }

		
	condition:
	
		dotnet.is_dotnet and $s1

}