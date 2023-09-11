import "dotnet"

rule win_asyncrat_bytecodes
{
	meta:
		author = "Matthew @ Embee_Research"
		created = "2023/09/10"
		description = "Detects bytecodes present in unobfuscated AsyncRat Samples. Rule may also pick up on other Asyncrat-derived malware (Dcrat/venom etc)"
		sha_256 = "0e65aadd6c3aede82c01e66723fd3688ffa3a0ab6600c8556b393c5f2615a15d"
		
	strings:
	
		$s1 = {72 ?? ?? ?? ?? 80 ?? ?? ?? ?? 72 ?? ?? ?? ?? 80 ?? ?? ?? ?? 72 ?? ?? ?? ?? 80 ?? ?? ?? ?? 72 ?? ?? ?? ?? 80 ?? ?? ?? ?? 72 ?? ?? ?? ?? 80 ?? ?? ?? ?? 72 ?? ?? ?? ?? 80 ?? ?? ?? ?? 72 ?? ?? ?? ?? 80 ?? ?? ?? ?? 72 ?? ?? ?? ?? 80 ?? ?? ?? ?? 72 ?? ?? ?? ?? 80 ?? ?? ?? ?? 72 ?? ?? ?? ?? 80 ?? ?? ?? ?? 72 ?? ?? ?? ?? 80 ?? ?? ?? ?? 72 ?? ?? ?? ?? 80 ?? ?? ?? ?? 72 ?? ?? ?? ?? 80 ?? ?? ?? ?? ?? 80 ?? ?? ?? ?? 72 ?? ?? ?? ?? 80 ?? ?? ?? ?? 72 ?? ?? ?? ?? 80 ?? ?? ?? ?? 2A}
		
	condition:
			dotnet.is_dotnet 
		and
			filesize < 7000KB 
		and 
			$s1
}     


/*
	
	
	72 ?? ?? ?? ??  ldstr     "DoR2EwFoczeVD6l9ZOeBSTDWqq4Q9CyGPyExsflJjWgYfC3ghVH18FN3Xcc3SKL9rpgmI5EBk/MTtCjWaplLJw=="
	80 ?? ?? ?? ??  stsfld    string Client.Settings::Ports
	72 ?? ?? ?? ??  ldstr     "9XbAAh5WKI2oZjzfOsD/a8Kt/T1UNLbJcNMCaFV9eMfCyYCkCfXLtZFwlDrO0pnN9N5TnOodJhfp1o4a2ztdag=="
	80 ?? ?? ?? ??  stsfld    string Client.Settings::Hosts
	72 ?? ?? ?? ??  ldstr     "Z5pZYvRJIFTn8wlNIbceeqsxsKyiih9zS9G1Q49QpoEQOhv8FIVYhJy3JtaDzo7YHrinzRvWHLMY6KkdaCxT9w=="
	80 ?? ?? ?? ??  stsfld    string Client.Settings::Version
	72 ?? ?? ?? ??  ldstr     "lv3eVVbrtyehpFQQS+O85pqbqHpE531GsoTORjAIVkmXnn29fizpHaeprUcfXfR7i1rDsUVnA0uHFazCOt353g=="
	80 ?? ?? ?? ??  stsfld    string Client.Settings::Install
	72 ?? ?? ?? ??  ldstr     "%AppData%"
	80 ?? ?? ?? ??  stsfld    string Client.Settings::InstallFolder
	72 ?? ?? ?? ??  ldstr     ""
	80 ?? ?? ?? ??  stsfld    string Client.Settings::InstallFile
	72 ?? ?? ?? ??  ldstr     "VklmeGZxcnlVVHlaVUJHRENCQXZiWVZZSXNleElNN1o="
	80 ?? ?? ?? ??  stsfld    string Client.Settings::Key
	72 ?? ?? ?? ??  ldstr     "vx/BE7jbRUB6mf7JvBe7Aqms5ens79dF75erQeF42sT5vvO+4N9X2zk0aqxqkuguWA/A06An2byEZbqi5N4oc6eDd74t2bt19gesw0UIL8c="
	80 ?? ?? ?? ??  stsfld    string Client.Settings::MTX
	72 ?? ?? ?? ??  ldstr     "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"
	80 ?? ?? ?? ??  stsfld    string Client.Settings::Certificate
	72 ?? ?? ?? ??  ldstr     "xYuvE6ES2q02iyx0gj+TcxpQsqddzdkIJrpkxnhqM1VY6AGnW9K7iueX76+kb51aZY1MQHOImE+WAxBe/9TWW8PghqnYJs+uiWFcbqIrt7wBNgYAZIb4fWIYK6I8PvGWTdMT0vp5d1eejCO3WE2kAMEeZpGjb68AQ5PP+dh1Wp3O0VUq7s2iJGVMSVGN135sxYJU8wDgauyFnkLJSJeLk1O3e5wj8ldO2VmBZYAsUnmHz13Us3I3PoAxFiTxlTLjhRPFRIsbCqEP6xNQ3kDkFKuLpFSL/blpFfMjQmQ5BZa89JW71VVphnSL2FKVSNQKCMnGVL3nP821stfO7+UaXigZoiCSHiCC8Xr7nEzpDlG2RgMUwDucpB1mvt98IYaMGq/0fG4jfeTA55MeYaYohWWyA2LtRP0RbW/rwb/1i8zbRO8ZE2Ija3PodY2RvbPdbjE54kTNtjBgzf6K8E81X7btQR8c8BZUMdOwxVl75qDT2H63rZEaMl77jloAE/cEkIXrsX7+rZ6B7a6lMZmYLElRc8LWfLlSZmThfBDIK9YeXkFtWJRgA93O4gg7E3lUzMJu0g5B7msUktrpU4528r3AjTy2eoctSxjuRDsr/e6TOwdUc8gl8ZVMOYDhisupmEJt9e0OLgzrGcKtKqXbyBW04KCUkm1FIO9+PAZxSUEyaMGCsQHWKj0svFFlqaKqYzWAFMT6DiqSi2BAj6+og84aRcK3N4c6p98aY4O5HOqEDAI1j2YIqfDIzPbNiJdDHFejRE0OLkZnxtDO6Rvx2mqmHyrBbw5jnawfKvTDhq9ycPJI5uzSx4Z/3IZFkvoVxDnyZe8bPXlEi1VKolNoVTKKe7QZ0Nmvh/mkccBQprZplaC6NMjrI7NmgMkSath9a+NWtUN7wdN42ZgRVtQNlaq9f0psTGTNdCMC+zYJWBRLXIGFGZDtAcys9c5CjJcRCGuCXgAlNFlzNX4rlEJLOQ=="
	80 ?? ?? ?? ??  stsfld    string Client.Settings::Serversignature
	72 ?? ?? ?? ??  ldstr     "BiqtBx0xjRuDe2Zg2dcC8J1KoWKNoffEUKHBE7OdLr8W1kZJuL2JQIK4EKh/Pufzqq/B5pa67ljqVHKVKUgg3g=="
	80 ?? ?? ?? ??  stsfld    string Client.Settings::Anti
	72 ?? ?? ?? ??  ldstr     "G8C7Y9ipusvdFZrZg53dgXEaAzb3TOWL7VsYVVsds6b1TJw/sOxoqkvDGfYz+RYqo3+w0n9qUFWDYPpb42n2VA=="
	80 ?? ?? ?? ??  stsfld    string Client.Settings::Pastebin
	72 ?? ?? ?? ??  ldstr     "naNafWycahxvYmxnrme7My+ztnu57353mXdbSDHHMxlJb6oV1x/IXzsIZ33nJ4eakzCYRHnyv/GyGZXz+Zl1ng=="
	80 ?? ?? ?? ??  stsfld    string Client.Settings::BDOS
	??          	ldnull
	80 ?? ?? ?? ??  stsfld    string Client.Settings::Hwid
	72 ?? ?? ?? ??  ldstr     "3"
	80 ?? ?? ?? ??  stsfld    string Client.Settings::Delay
	72 ?? ?? ?? ??  ldstr     "jB9JCdgvxk7Z2AuNc0VtOVQrqhLj+ZMZIyXzhSmN2MgzVeR28iM6y+dsiKW3WJmuyx3ffevzkyVizOEQWAISeg=="
	80 ?? ?? ?? ??  stsfld    string Client.Settings::Group
	2A          	ret

*/