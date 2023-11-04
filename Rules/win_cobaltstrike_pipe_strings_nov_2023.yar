rule win_cobaltstrike_pipe_strings_nov_2023
{
	meta:
		author = "Matthew @ Embee_Research"
		created = "2023/11/04"
		description = "Detects default strings related to cobalt strike named pipes"
		sha_256 = "99986d438ec146bbb8b5faa63ce47264750a8fdf508a4d4250a8e1e3d58377fd"
		sha_256 = "090402a6e2db12cbdd3a889b7b46bb7702acc0cad37d87ff201230b618fe7ed5"
		sha_256 = "eb2b263937f8d28aa9df7277b6f25d10604a5037d5644c98ee0ab8f7a25db7b4"
		
	strings:
		$s1 = "%c%c%c%c%c%cMSSE-%d-server"
		$s2 = "ConnectNamedPipe"
		$s3 = "CreateNamedPipeA"
		$s4 = "TlsGetValue"
		
		
	condition:
		(all of ($s*))
		and
		filesize < 500KB
		

}