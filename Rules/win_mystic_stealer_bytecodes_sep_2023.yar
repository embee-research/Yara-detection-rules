rule win_mystic_stealer_bytecodes_sep_2023
{ 
	meta:
		author = "Matthew @ Embee_reserch"
		date = "2023/09/21"
		sha256 = "ef9fce75334befe0b435798c0b61dab1239ea5bc62b97654943676dd96dc6318"
		sha256 = "36d8cb1447e2c5da60d2b86bf29856919c25f8e71a17f1d0d61d03c5e0505e4b"
		sha256 = "e907c22288dacb37efa07481fef7a0d4ec0ce42954f12b2572ea7f5ffeecf313"
	strings:
		
		$s1 = {99 d3 d8 c5}
		$s2 = {99 b7 66 df}
		$s3 = {cb 45 92 f8}
		$s4 = {7b cc e1 54}
		$s5 = {7b 9c 29 17}
		$s6 = {01 c4 fb 83}
		$s7 = {b6 0f 74 e3}
		$s8 = {93 58 b5 ee}
		$s9 = {81 d9 df be}
		$s10 = {7b d8 62 00}
		$s12 = {81 d9 df be}
		$s13 = {7b d8 62 00}
		$s14 = {77 4a bc ac}
		
	condition:
	
		(all of them)

}
