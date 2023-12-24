rule win_marsStealer_encryption_bytecodes
{
	meta:
		author = "Matthew @ Embee_Research"
		created = "2023/12/24"
		description = "Encryption observed in MarsStealer"
		sha_256 = "7a391340b6677f74bcf896b5cc16a470543e2a384049df47949038df5e770df1"
		
	strings:
	
		$s1 = {31 2d 3d 31 73 30 02 39 c0 74 0a 5b 70 61 73 64 6c 30 71 77 69 8d 5b 01 8d 52 01 39 eb 75 03 83 eb 20 39 ca}
	condition:
		$s1 
		

}

/*
                             LAB_0043c021+5      	                            XREF[0,1]:   0043c019 (j)   
        0043c021 31  2d  3d  31  73  30          	XOR        dword ptr [DAT_3073313d ],EBP
        0043c027 02  39                       		ADD        BH ,byte ptr [param_1 ]
        0043c029 c0  74  0a  5b  70              	SHL        byte ptr [param_2  + param_1 *0x1  + 0x5b ],0x70
        0043c02e 61                           		POPAD
        0043c02f 73  64                       		JNC        LAB_0043c095
        0043c031 6c                           		INSB       ES :EDI ,param_2
        0043c032 30  71  77                    		XOR        byte ptr [param_1  + 0x77 ],param_2
        0043c035 69  8d  5b  01  8d  52  01         IMUL       param_1 ,dword ptr [EBP  + 0x528d015b ],0x75eb39
                 39  eb  75
        0043c03f 03  83  eb  20  39  ca           	ADD        EAX ,dword ptr [EBX  + 0xca3920eb ]


*/