import "dotnet"

rule win_xworm_bytestring
{
	meta:
		author = "Matthew @ Embee_Research"
		created = "2023/08/27"
		description = "Detects bytestring present in unobfuscated xworm"
		sha_256 = "8948b34d471db1e334e6caa00492bd11a60d0ec378933386b0cb7bc1b971c102"
		sha_256 = "52634ade55558807042eae35e2777894e405e811102e980a2e2b25d151fde121"

		
	strings: 
	
		$p1 = { 72 [4] 16 28 [4] 16 33 ?? 72 [4] 0C 38 [4] 11 ?? 72 [4] 16 28 [4] 16 33 ?? 72 [4] 0C 38 [4] 11 ?? 72 [4] 16 28 [4] 16 33 ?? 72 [4] 0C 38 [4] 11 ?? 72 [4] 16 28 [4] 16 33 ?? }
	
	condition:
			dotnet.is_dotnet 
		and
			$p1
		
		

}