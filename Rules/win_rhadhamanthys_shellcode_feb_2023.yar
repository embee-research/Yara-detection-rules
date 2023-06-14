rule win_rhadhamanthys_shellcode_feb_2023
{
	meta:
		author = "Embee_Research @ Huntress Labs"
		created = "2023/02/24"
		reference_sample = "c1f0d2e7b5f3cbdde3a9b61e4fe8aa9ddff6311103ede6771a030b837ecd18e2"
	strings:
		
		$hashing = {8b f0 c1 e6 13 c1 e8 0d 0b f0 0f be c1 8a 4a 01 03 c6 42}
		
		// To Help with additional filtering. 
		$shellcode = {E8 ?? 00 [2-10] 90 90 90 }

		//Change to this for broader search, but hits on other malware families
		//$hashing_with_wildcard = {8b f0 c1 e6 ?? c1 e8 ?? 0b f0 0f be c1 8a 4a 01 03 c6 42}

		/*
		Hashing Routine from Unpacked Rhadamanthys Malware
		Unconfirmed as to whether this routine is shared with other malware families. 
		00000419 8b  f0           MOV        ESI ,EAX
		0000041b c1  e6  13       SHL        ESI ,0x13
		0000041e c1  e8  0d       SHR        EAX ,0xd
		00000421 0b  f0           OR         ESI ,EAX
		00000423 0f  be  c1       MOVSX      EAX ,CL
		00000426 8a  4a  01       MOV        CL ,byte ptr [EDX  + 0x1 ]
		00000429 03  c6           ADD        EAX ,ESI
		0000042b 42               INC        EDX
		*/
		
		
	condition:
		all of them
}
