rule win_ursnif_patterns_oct_2022
{
	meta:
		author = "Embee_Research @ Huntress"
		created = "2022/10/14"
	strings:
		
		$ursnif = {41 c1 e8 02 45 33 d2 45 8b d9 45 85 c0 74 2f 48 2b ca 83 7c 24 28 00 8b 04 11 44 8b c8 74 0a 85 c0 75 06 44 8d 40 01}
		$script = "65,193,232,2,69,51,210,69,139,217,69,133,192,116,47,72,43,202,131,124,36,40,0,139,4,17,68,139,200,116,10,133,192,117,6,68,141,64,1"
		
		
	condition:
		any of them
}