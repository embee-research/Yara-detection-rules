
rule win_redline_updated_bytecodes_oct_2023
{
	meta:
		author = "Matthew @ Embee_Research"
		created = "2023/10/11"
		description = "Configuration related bytecodes in redline .net files"
		sha_256 = "0cc3a0f8b48ef8d8562b9cdf9c7cfe7f63faf43a5ac6dc6973dc8bf13b6c88cf"
		
	strings:

		$s_1 = {   
				20 ?? ?? ?? ?? 											// ldc.i4
				2B 00       											// br.s
				28 ?? ?? ?? 2B 											// Call
				80 ?? ?? ?? 04 											// stsfld
				(20 ?? ?? ?? ?? 2B00 28 ?? ?? ?? 2B | 72 ?? ?? ?? 70)   // ldc.i4, br.s, call OR ldstr
				80 ?? ?? ?? 04      									// Call
				(20 ?? ?? ?? ?? 2B00 28 ?? ?? ?? 2B | 72 ?? ?? ?? 70)   // ldc.i4, br.s, call OR ldstr
				80 ?? ?? ?? 04 											// Call		
				20 ?? ?? ?? ?? 											// ldc.i4
				2B00            										// br.s
				28 ?? ?? ?? 2B      									// Call
				80 ?? ?? ?? 04 											// stsfld
				2A 														// ret
			}
		
		$s_2 = "mscoree.dll" 
		
	condition:
		
		$s_1 and $s_2
		

}