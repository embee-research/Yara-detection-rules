rule win_qak_js_loader_jun_2023
{
	meta:
		author = "Embee_Research @ Huntress"
		desc = "Simple detection for Qakbot javascript loaders found on Malware Bazaar"
		created = "2023/06/14"
		hash = "5c666d42ddbf63e7b6e5256e360b9b627a8f6383db3b040c888ed662123ca8cf"
		hash = "174df60ab76cf134aed2dc55c0eb31bbf27199aaf5d77a5a7371be192c9ab3a3"
		hash = "dc380c6947c5f8de2586ab7baf30b36b6a9426932323cb2096af2c5f4e2c344d"
		hash = "e43fce049074b91782ec0c826b7ce89402dfed3053e23b15d8472264b63ebbc8"
	strings:
		/*
		  f = "function"
		  D = "constructor"
		, C = "hasOwnProperty"
		  ['WR81W4C','mCk5WPVcHHK','DGeOutuF','W6FdVmkKbW','Dmo+t8oYgvq','dCoknCkaW5m','WRHGmmoGW47dTa','W5ePDGO']
		*/
		$s1 = /\s\w{1,3}\s+=\s+["']constructor['"]/ ascii nocase 
		$s2 = /\s\w{1,3}\s+=\s+["']function['"]/ ascii nocase 
		$s3 = /\s\w{1,3}\s+=\s+["']hasownproperty['"]/ ascii nocase 
		$s4 = /(['"][a-zA-Z0-9\=\+\/]{5,20}['"],?){50,100}/ ascii 
		
	condition:
		(all of them) and filesize < 500KB and filesize > 50KB and not uint16(0) == 0x5a4d
}