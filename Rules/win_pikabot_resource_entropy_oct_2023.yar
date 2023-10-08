
import "pe"
import "math"

rule win_pikabot_resource_entropy_oct_2023
{
	meta:
		author = "Matthew @ Embee_Research"
		created = "2023/10/03"
		description = "Pikabot Loaders embedding encrypted inside of numerous png images"
		sha_256 = "936247d9a0ce76bed17f03430186abb9ecafa88ef3a968cdd46c5b0a24a5cc3f"
		sha_256 = "2c7b7c3ec8a6a835e07c8feed401460e185388f59ea5fc8aa8038d2b75815666"
		sha_256 = "00239c55d7135aa06e21ace557a3e8bf3818c2e07051c84753209e7348b6a426"
		sha_256 = "5f218eeb83c936d88b65ec3f3052d8c53f58775dacc04bedc91bd388fb7bb885"
		sha_256 = "6bea3ecd1f43bdcc261719fb732fcf27e82ed6f4b086616925291a733f358a26"
		sha_256 = "966042f3e532b6abce7d96bbdb91dc4561b32a4b0b9eec7b08b4f1024c2da916"
		sha_256 = "951c906a1fa179050d30c06849d42e49a295dd1baad91efb244b2e5486b5801d"
		sha_256 = "a06bd2623c389f2547d0bf750ca720ab7a74c90982267aad49ba31d5de345288"
		sha_256 = "aeb2bf8898636b572b0703d9ddb90b9a4c5c6db9eee631ee726ad753f197ac12"
		
	strings:
		$s1 = "ARROW-DOWN" wide
		$s2 = "ARROW-LEFT" wide
		$s3 = "ARROW-RIGHT" wide
		
		
	condition:
			pe.DLL
		and
			(all of ($s*))
		and 
			pe.number_of_resources > 25	
		and 
			pe.sections[3].raw_data_size > 400KB
		and 
			math.entropy(pe.sections[3].raw_data_offset,pe.sections[3].raw_data_size) > 7.5
		
		

}