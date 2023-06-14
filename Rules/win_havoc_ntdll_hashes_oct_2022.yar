rule win_havoc_ntdll_hashes_oct_2022
{
	//Detects ntdll API hashes used in Havoc C2 Demon payloads
    
	meta:
		author = "embee_research @ HuntressLabs"
		vendor = "Huntress Research" 
		date = "2022/10/11"
		description = "Detection of havoc demons via hardcoded ntdll api hashes"
	strings:
		
		// Syscall Hashes
		$nt_hash1 = {53 17 e6 70} //0x70e61753 == ntdll.dll
		$nt_hash2 = {43 6a 45 9e} //0x9e456a43 == LdrLoadDll
		$nt_hash3 = {ec b8 83 f7} //0xf783b8ec == NtAllocateVirtualMemory
		$nt_hash4 = {88 28 e9 50} //0x50e92888 == NtProtectVirtualMemory
        
        
		$nt_hash5 = {f6 99 5a 2e} //0x2e5a99f6 == LdrGetProcedureAddress
		$nt_hash6 = {da 81 b3 c0} //0xc0b381da == NtAllocateHeap
		$nt_hash7 = {d7 71 ba 70} //0x70ba71d7 == RtlFreeHeap
		$nt_hash8 = {88 2b 49 8e} //0x8e492b88 == RtlExitUserThread
		$nt_hash9 = {ef f0 a1 3a} //0x3aa1f0ef == RtlExitUserProcess
		$nt_hash10 = {f5 39 34 7c} //0x7c3439f5 == RtlRandomEx
		$nt_hash11 = {70 f2 ab 35} //0x35abf270 == RtlNtStatusToDosError
		$nt_hash12 = {1d aa a3 3c} //0x3ca3aa1d == RtlGetVersion
		$nt_hash13 = {11 b2 8f f7} //0xf78fb211 == RtlCreateTimerQueue
		$nt_hash14 = {4c 7c de a5} //0xa5de7c4c == RtlCreateTimer
		$nt_hash15 = {90 fe 61 95} //0x9561fe90 == RtlDeleteTimerQueue
		$nt_hash16 = {d0 ee 33 77} //0x7733eed0 == RtlCaptureContext
		$nt_hash17 = {a9 af 4b 55} //0x554bafa9 == RtlAddVectoredExceptionHandler
		$nt_hash18 = {0e 21 0c 88} //0x880c210e == RtlRemoveVectoredExceptionHandler
		$nt_hash19 = {3d 13 8e 8b} //0x8b8e133d == NtClose
		$nt_hash20 = {7d 74 58 ca} //0xca58747d == ZwCreateEvent
		
	condition:
		//PE or Shellcode or Shellcode
		//Leave as "3 of them" for more robust (but compute expensive) searching
		(3 of them) and (uint16(0) == 0x5a4d or uint16(0) == 0x00e8 or uint16(0) == 0x4856)
}