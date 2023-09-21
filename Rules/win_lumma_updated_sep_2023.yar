rule win_lumma_update_simple_strings_sep_2023
{
	meta:
		author = "Matthew @ Embee_Research"
		created = "2023/09/13"
		description = ""
		sha_256 = "898a2bdbbb33ccd63b038c67d217554a668a52e9642874bd0f57e08153e6e5be"
		
	strings:
		
		$s1 = "Do you want to run a malware ?" wide
		$s2 = "c2sock" wide
		$s3 = "TeslaBrowser/5" wide
		$s4 = "Crypt build to disable this message" wide

	condition:
		uint16(0) == 0x5a4d
		and
		filesize < 5000KB
		and
		(all of ($s*))



}