rule win_berbew_strings_dec_2023
{
	meta:
		author = "Matthew @ Embee_Research"
		created = "2023/12/24"
		description = "Strings observed in Berbew malware."
		sha_256 = "24dc0af3c51118697df999d8bffcdfc9cbf0d07f2630473450dd826a1ae4b9ae"
		
	strings:
	
		$s1 = "This KEWL STUFF was coded by V. V. PUPKIN"
		$s2 = "REAL CASH, REAL BITCHEZ"
		$s3 = "Please, enter your Card Number"
		
	condition:
		all of them
		

}

