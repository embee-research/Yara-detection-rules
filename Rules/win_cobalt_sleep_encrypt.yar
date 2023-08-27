rule win_cobalt_sleep_encrypt
{
	meta:
		author = "Matthew @ Embee_Research"
		created = "2023/08/27"
		description = "Detects Sleep Encryption Logic Found in Cobalt Strike Deployments"
		sha_256 = "26b2f12906c3590c8272b80358867944fd86b9f2cc21ee6f76f023db812e5bb1"
		
	strings:
	
		/*
		Encryption Round 1 / Decrypt Code
		0000000000CCFD2E | 4E:8B0408                | mov r8,qword ptr ds:[rax+r9]           
		0000000000CCFD32 | B8 4FECC44E              | mov eax,4EC4EC4F                       
		0000000000CCFD37 | 41:F7E3                  | mul r11d                               
		0000000000CCFD3A | 41:8BC3                  | mov eax,r11d                           
		0000000000CCFD3D | C1EA 02                  | shr edx,2                              
		0000000000CCFD40 | 41:FFC3                  | inc r11d                               
		0000000000CCFD43 | 6BD2 0D                  | imul edx,edx,D                         
		0000000000CCFD46 | 2BC2                     | sub eax,edx                            
		0000000000CCFD48 | 8A4C18 18                | mov cl,byte ptr ds:[rax+rbx+18]        
		0000000000CCFD4C | 41:300C38                | xor byte ptr ds:[r8+rdi],cl            
		0000000000CCFD50 | 48:8B43 10               | mov rax,qword ptr ds:[rbx+10]          
		0000000000CCFD54 | 41:8BFB                  | mov edi,r11d                           
		0000000000CCFD57 | 4A:3B7C08 08             | cmp rdi,qword ptr ds:[rax+r9+8]        
				
		Encryption Round 2 / Possible Re-encrypt Code
		0000000000CCFD93 | 49:8BF9                  | mov rdi,r9                           
		0000000000CCFD96 | 4C:8B03                  | mov r8,qword ptr ds:[rbx]            
		0000000000CCFD99 | B8 4FECC44E              | mov eax,4EC4EC4F                     
		0000000000CCFD9E | 41:F7E1                  | mul r9d                              
		0000000000CCFDA1 | 41:8BC1                  | mov eax,r9d                          
		0000000000CCFDA4 | C1EA 02                  | shr edx,2                            
		0000000000CCFDA7 | 41:FFC1                  | inc r9d                              
		0000000000CCFDAA | 6BD2 0D                  | imul edx,edx,D                       
		0000000000CCFDAD | 2BC2                     | sub eax,edx                          
		0000000000CCFDAF | 8A4C18 18                | mov cl,byte ptr ds:[rax+rbx+18]      
		0000000000CCFDB3 | 42:300C07                | xor byte ptr ds:[rdi+r8],cl          
		0000000000CCFDB7 | 48:FFC7                  | inc rdi                              
		0000000000CCFDBA | 45:3BCB                  | cmp r9d,r11d                         
		
		*/
		
		
		$r1_nokey = {4E 8B 04 08 B8 ?? ?? ?? ?? 41 F7 E3 41 8B C3 C1 EA 02 41 FF C3 6B D2 0D 2B C2 8A 4C 18 18 41 30 0C 38 48 8B 43 10 41 8B FB 4A 3B 7C 08 08}

		$r2_nokey = {49 8B F9 4C 8B 03 B8 ?? ?? ?? ?? 41 F7 E1 41 8B C1 C1 EA 02 41 FF C1 6B D2 0D 2B C2 8A 4C 18 18 42 30 0C 07 48 FF C7 45 3B CB}
		
	condition:
		//uint16(0) == 0x5a4d and
		//filesize < 3000KB and
		($r1_nokey or $r2_nokey)
		

}