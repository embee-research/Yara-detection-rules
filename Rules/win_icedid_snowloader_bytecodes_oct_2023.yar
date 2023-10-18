import "pe"
rule win_icedid_snowloader_bytecodes_oct_2023
{
	meta:
		author = "Matthew @ Embee_Research"
		created = "2023/08/27"
		sha_256 = "e096de90f65ff83ed0e929b330aa765a8e2322625325fb042775bff1748467cc"
		sha_256 = "e87928fcddf13935c91a0b5577e28efd29bb6a5c1d98e5129dec63e231601053"
		sha_256 = "82a01607ebdcaa73b9ff201ccb76780ad8de4a99dd3df026dcb71b0f007456ed"

	strings:
		$s_1 = {4c 77 26 07} //Ror13 hashes
		$s_2 = {58 a4 53 e5}
		$s_3 = {10 e1 8a c3}

	condition:
		(all of ($s*))
		
		and
		
		pe.number_of_exports > 20

}