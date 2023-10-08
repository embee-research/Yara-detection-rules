

rule win_pikabot_loader_bytecodes_oct_2023
{
	meta:
		author = "Matthew @ Embee_Research"
		created = "2023/10/03"
		description = "Detects bytecodes in recent PikaBot Loaders"
		sha_256 = "778b6797bb9c9d2f868d3faaaf6b36ce3f06178c133bb592c5345c95ffb034a9"
		sha_256 = "e26d44d740b4edbd37fa6196dcc9171e49e711d8ce64f67aae36c4299e352108"
		sha_256 = "2d212cacc4767ef4383bdf462a9bb8aaf87f0b3c55b4c2f4a47c97c710ec1cd8"
		
	strings:
		$s1 = { 8b 59 64 a1 58 00 ?? ?? 8b 8e d0 00 00 00 2b c1 2d d9 f1 3e 41 0f af da 09 46 20 a1 34 dd ?? ?? 8b d3 2b 88 a0 00 00 00 2b 0d bc ff ?? ?? 81}
		
		//$original = {8b 59 64 a1 58 00 9b 67 8b 8e d0 00 00 00 2b c1 2d d9 f1 3e 41 0f af da 09 46 20 a1 34 dd 96 67 8b d3 2b 88 a0 00 00 00 2b 0d bc ff 9a 67 81 c1 22 10 2c 00 c1 ea 18}
		
	condition:
		$s1

}