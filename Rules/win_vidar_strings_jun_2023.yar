rule win_vidar_strings_jun_2023
{
	meta:
		author = "Matthew @ Embee_Research"
		created = "2023/06/06"
		description = "Detection of Vidar Stealer and Variants via strings present in final unpacked payloads"
		sha_256 = "29edb23e89b1512a4c044133cbafc863eb2710f8d8d3828ee0583cd1c528da60"
		md5 = "7915069b383d07cf16180aecc449848f"
		
	strings:
		
		$s1 = "Electrum\\Wallets\\"
		$s2 = "Chia Wallet"
		$s4 = "Opera Stable"
		$s5 = "chrome-extension"
		$s6 = "KeePassXC-Browser"
		$s7 = "GeroWallet"
		$s8 = "Martian Wallet"
		$s9 = "Exodus Web3 Wallet"
		
		$base64 = /[a-zA-Z0-9\=\+]{15,30}=/
		
	condition:
		uint16(0) == 0x5a4d and
		filesize < 3000KB and
		(4 of ($s*)) and 
		#base64 > 10
		

}