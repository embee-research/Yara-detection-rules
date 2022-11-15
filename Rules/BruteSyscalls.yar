rule BruteSyscallHashes
{
	//Looks for API hashes present in Brute Ratel Badger Payloads. 
	meta:
		author = "Embee_Research @ Huntress"
		vendor = "Huntress"
		created = "2022/10/12"
	strings:
		
		$hash1 = {89 4d 39 8c} //NtProtectVirtualMemory
		$hash2 = {bd ca 3b d3} //NtAllocateVirtualMemory
		$hash3 = {b2 c1 06 ae} //NtWaitForSingleObject
		$hash4 = {74 eb 1d 4d} //NtCreateThreadEx
	
	condition:
		//0x5a4d == regular pe/dll
		//0x00e8 == start of Brute shellcode 
		(2 of them) and (uint16(0) == 0x5a4d or uint16(0) == 0x00e8)
		
}