import "pe"

rule Merlin_x64_agent_PE_Precompiled
{
	condition:
		pe.is_pe
}

rule Merlin_Premade_x64_Agent
{
	meta: 
		description = "Detects Merlin Framework x64 Agent (Precompiled v1.2.1)"
		info = "This rule matches the precompiled Merlin agent that comes with the Merlin server"
		author = "Michael Andersen"
		reference = "https://github.com/Ne0nd0g/merlin/releases"
		date = "2022-01-28"
		hash0 = "1cc95705b15ac7b45192d304d2453c6eccb8cf65aba02563b11d2ca973c7212f"
		hash1 = "0678d021eea3bcf377bebc76c4f91b74c29db1e48e70c371423c9944a1ec25d4"

	strings:
		$STR1 = { 4? 89 44 ?? ?? 4? 89 5c ?? ?? 4? 8d 3d ?? ?? ?? ?? 4? 8d ?? ?? ?? ?? ?? ?? 4? 89 5? ?? 4? 89 5? ?? 4? 89 1? 4? 89 6? ?? b8 ?? ?? ?? ?? 0f a2 89 c6 83 f8 ?? 74 ?? 81 fb ?? ?? ?? ?? 75 ?? 81 fa ?? ?? ?? ?? 75 ?? 81 f9 ?? ?? ?? ?? 75 ?? c6 05 ?? ?? ?? ?? ?? c6 05 ?? ?? ?? ?? ?? b8 ?? ?? ?? ?? 0f a2 89 05 ?? ?? ?? ?? 4? 8b 05 ?? ?? ?? ?? 4? 85 c0  }
		$STR2 = "**jose.JSONWebKey"
		$STR3 = "go.dedis.ch/fixbuf" nocase
		$STR4 = "jose.keyDecrypter"
		$STR5 = "Payload"
		$STR6 = "go.dedis.ch/kyber" nocase
		$STR7 = "*hpack.DecodingError"
		$STR8 = "undecryptablePackets"
		$STR9 = "github.com/mattn" nocase
		$STR10 = "github.com/fatih" nocase
		$STR11 = "github.com/google" nocase
		$STR12 = "github.com/satori" nocase
		$STR13 = "github.com/!ne0nd0g" nocase
		$STR14 = "github.com/cretz" nocase
		$STR15 = "github.com/refraction-networking" nocase
		$STR16 = "github.com/lucas-clemente" nocase
		$STR17 = "github.com/marten-seemann" nocase

	condition:
		15 of them
}
