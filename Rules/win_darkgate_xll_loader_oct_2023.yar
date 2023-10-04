
rule win_darkgate_xllloader_oct_2023
{
	meta:
		author = "Matthew @ Embee_Research"
		created = "2023/10/03"
		description = "Detects XLL Files Related to DarkGate"
		sha_256 = "091b7c16791cf976e684fe22ee18a4099a4e26ec75fa145b85dd14603b466b00"
		sha_256 = "305de78353b0d599cd40a73c7e639df7f5946d1fc36691c8f7798a99ee6835e7"
		sha_256 = "98c59262ad396b4da5b0a3e82f819923f860e974f687c4fff9b852f25a56c50f"
		sha_256 = "27ec297e1fc34e29963303782ff881e74f8bd4126f4c5be0c4754f745d85f79a"
		sha_256 = "392fd4d218a8e333bc422635e48fdfae59054413c7a6be764c0275752d45ab23"
		sha_256 = "9a34b32d0a66dd4f59aeea82ef48f335913c47c6ca901ab109df702cd166892f"

	strings:
		$s1 = "xlAutoOpen" wide ascii
		$s2 = { 49 ?? ?? 4c ?? ?? 48 ?? ?? 48 ?? ?? 02 e8 ?? ?? ?? ?? 48 ?? ?? 31 ?? 48 ?? ?? 01 48 ?? ?? 41 ?? ?? ?? ?? 30 ?? 48 ?? ?? 01 49 ?? ?? 75 ?? }
		
	condition:
			(all of ($s*))
		

}