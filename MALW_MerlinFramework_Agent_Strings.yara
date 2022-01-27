import "pe"

rule Merlin_agent_is_DLLPE
{
	condition:
		pe.is_pe and pe.characteristics & pe.DLL
}

rule Merlin_Agent_x86_x64_Exports
{
	condition:
		pe.exports("Run") and
		pe.exports("DllInstall") and
		pe.exports("DllRegisterServer") and
		pe.exports("DllUnregisterServer") and
		pe.exports("Merlin") and
		pe.exports("VoidFunc") and
		pe.exports("_cgo_dummy_export")
}

rule Merlin_Agent_Has_Sections
{
	condition:
		pe.number_of_sections >= 18
}

rule Merlin_Agent_x86_x64_Strings
{
	meta: 
		description = "Detects Merlin Framework Agent"
		info = ""
		author = "Michael Andersen"
		reference = "Not set"
		date = "2022-01-27"
		hash0 = "0678d021eea3bcf377bebc76c4f91b74c29db1e48e70c371423c9944a1ec25d4"

	strings:
		$STR1 = "abcdefghijklmnopqrstuvwxyz" wide ascii
		$STR2 = "github.com/cheekybits" ascii nocase
		$STR3 = "github.com/cretz" ascii nocase
		$STR4 = "github.com/fatih" ascii nocase
		$STR5 = "github.com/lucas-clemente" ascii nocase
		$STR6 = "github.com/marten-seemann" ascii nocase
		$STR7 = "github.com/mattn" ascii nocase
		$STR8 = "github.com/Ne0nd0g" ascii nocase
		$STR9 = "github.com/refraction-networking" ascii nocase
		$STR10 = "github.com/satori" ascii nocase
		$STR11 = "merlin-agent" ascii nocase
		$STR12 = "agent.executeJob" ascii nocase

	condition:
		$STR1 and $STR11 and $STR12 and
		8 of ($STR2,$STR3,$STR4,$STR5,$STR6,$STR7,$STR8,$STR9,$STR10)
}
