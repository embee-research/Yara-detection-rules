
import "pe"

rule win_redline_wextract_hunting_oct_2023
{
	meta:
		author = "Matthew @ Embee_Research"
		created = "2023/10/03"
		description = "Detects wextract archives related to redline/amadey"
		sha_256 = "37cb0c1d82fca0d95075ecdaf6d8863b68ccf55b060e0f70dc0614504ebf5436"
		
	strings:
		$s1 = "WEXTRACT.EXE" wide
		$s2 = "POSTRUNPROGRAM" wide
		$s3 = "POSTRUNPROGRAM" ascii
		
		$regex = /[a-zA-Z0-9]{6,10}\.exe/
		
	condition:
		(all of ($s*)) 
	and 
	
		6 < #regex 
	and 
		for 2 resource in pe.resources: (
		
			resource.name_string == "P\x00O\x00S\x00T\x00R\x00U\x00N\x00P\x00R\x00O\x00G\x00R\x00A\x00M\x00"
			or
			resource.name_string == "R\x00U\x00N\x00P\x00R\x00O\x00G\x00R\x00A\x00M\x00"
			
		)
	
	and
		for any resource in pe.resources: (
		
			resource.name_string == "E\x00X\x00T\x00R\x00A\x00C\x00T\x00O\x00P\x00T\x00"
			and
			uint16be(resource.offset) == 0x0100
			
		)
	and
		for any resource in pe.resources: (
		
			resource.name_string == "F\x00I\x00N\x00I\x00S\x00H\x00M\x00S\x00G\x00"
			and
			uint16be(resource.offset) == 0x3c4e
			
		)
	
		
		

}