rule win_redline_bytecodes_jan_2024
{
	meta:
		author = "Matthew @ Embee_Research"
		created = "2023/08/27"
		description = "Bytecodes found in late 2023 Redline malware"
		sha_256 = "ea1271c032046d482ed94c6d2c2c6e3ede9bea57dff13156cabca42b24fb9332"
		
	strings:
	
		$s1 = {00 00 7E ?? ?? ?? 04 7E ?? ?? ?? 04 28 ?? ?? ?? 06 17 8D ?? ?? ?? 01 25 16 1F 7C 9D 6F ?? ?? ?? 0A 13 ?? 16 13 ?? 38 }
		$s2 = "mscoree.dll" ascii
		
	condition:
	
		$s1 and $s2 
		and
		uint16(0) == 0x5a4d

		

}


/*

		 0x0000D683 00           IL_0053: nop
		 0x0000D684 00           IL_0054: nop
		 0x0000D685 7E3B000004   IL_0055: ldsfld    string Arguments::IP
		 0x0000D68A 7E3E000004   IL_005A: ldsfld    string Arguments::Key
		 0x0000D68F 28AC000006   IL_005F: call      string StringDecrypt::Read(string, string)
		 0x0000D694 17           IL_0064: ldc.i4.1
		 0x0000D695 8D7C000001   IL_0065: newarr    [mscorlib]System.Char
		 0x0000D69A 25           IL_006A: dup
		 0x0000D69B 16           IL_006B: ldc.i4.0
		 0x0000D69C 1F7C         IL_006C: ldc.i4.s  124
		 0x0000D69E 9D           IL_006E: stelem.i2
		 0x0000D69F 6FE000000A   IL_006F: callvirt  instance string[] [mscorlib]System.String::Split(char[])
		 0x0000D6A4 1308         IL_0074: stloc.s   V_8
		 0x0000D6A6 16           IL_0076: ldc.i4.0
		 0x0000D6A7 1309         IL_0077: stloc.s   V_9
		 0x0000D6A9 3828000000   IL_0079: br        IL_00A6


*/