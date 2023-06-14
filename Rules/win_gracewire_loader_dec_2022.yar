
rule win_gracewire_loader_dec_2022
{
	meta:
		author = "Embee_Research @ Huntress"
		created = "2022/12/12"
		description = "Yara rule to detect GraceWireLoader via usage of Stack Strings"
	strings:
		
		
		$ZwAllocateVirtualMemory = {c6 44 24 48 5a c6 44 24 49 77 c6 44 24 4a 41 c6 44 24 4b 6c c6 44 24 4c 6c c6 44 24 4d 6f c6 44 24 4e 63 c6 44 24 4f 61 c6 44 24 50 74 c6 44 24 51 65 c6 44 24 52 56 c6 44 24 53 69 c6 44 24 54 72 c6 44 24 55 74 c6 44 24 56 75 c6 44 24 57 61 c6 44 24 58 6c c6 44 24 59 4d c6 44 24 5a 65 c6 44 24 5b 6d c6 44 24 5c 6f} 
		
		
		$LdrGetProcedureAddress = {c6 44 24 50 4c c6 44 24 51 64 c6 44 24 52 72 c6 44 24 53 47 c6 44 24 54 65 c6 44 24 55 74 c6 44 24 56 50 c6 44 24 57 72 c6 44 24 58 6f c6 44 24 59 63 c6 44 24 5a 65 c6 44 24 5b 64 c6 44 24 5c 75 c6 44 24 5d 72 c6 44 24 5e 65 c6 44 24 5f 41 c6 44 24 60 64 c6 44 24 61 64 c6 44 24 62 72 c6 44 24 63 65 c6 44 24 64 73 c6 44 24 65 73 c6 44 24 66 00}
	
		$LdrLoadDLL = {c6 44 24 50 4c c6 44 24 51 64 c6 44 24 52 72 c6 44 24 53 4c c6 44 24 54 6f c6 44 24 55 61 c6 44 24 56 64 c6 44 24 57 44 c6 44 24 58 6c c6 44 24 59 6c}
		
		$ZwFreeVirtualMemory = {c6 44 24 30 5a c6 44 24 31 77 c6 44 24 32 46 c6 44 24 33 72 c6 44 24 34 65 c6 44 24 35 65 c6 44 24 36 56 c6 44 24 37 69 c6 44 24 38 72 c6 44 24 39 74 c6 44 24 3a 75 c6 44 24 3b 61 c6 44 24 3c 6c c6 44 24 3d 4d c6 44 24 3e 65 c6 44 24 3f 6d c6 44 24 40 6f c6 44 24 41 72 c6 44 24 42 79}
		
		
	condition:
		3 of them
		//add "and uint16(0) == 0x5a4d" for better performance but less accuracy
}