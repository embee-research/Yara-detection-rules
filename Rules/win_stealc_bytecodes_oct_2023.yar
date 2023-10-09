
rule win_stealc_bytecodes_oct_2023
{
	meta:
		author = "Matthew @ Embee_Research"
		created = "2023/08/27"
		description = "Bytecodes present in Stealc decoding routine"
		sha_256 = "74ff68245745b9d4cec9ef3c539d8da15295bdc70caa6fdb0632acdd9be4130a"
		sha_256 = "9f44a4cbc30e7a05d7eb00b531a9b3a4ada5d49ecf585b48892643a189358526"
		
	strings:
		$s1 = {8b 4d f0 89 4d f8 8b 45 f8 c1 e0 03 33 d2 b9 06 00 00 00 f7 f1 8b e5 5d c2 04 00}
		
		
		
	condition:
		
		(all of ($s*))
		

}