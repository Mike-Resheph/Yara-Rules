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

    strings:
        $STR1 = { 4? 89 44 ?? ?? 4? 89 5c ?? ?? 4? 8d 3d ?? ?? ?? ?? 4? 8d ?? ?? ?? ?? ?? ?? 4? 89 $
        $STR2 = "**jose.JSONWebKey"
        $STR3 = "go.dedis.ch/fixbuf"
        $STR4 = "jose.keyDecrypter"
        $STR5 = "Payload"
        $STR6 = "go.dedis.ch/kyber"
        $STR7 = "*hpack.DecodingError"
        $STR8 = "undecryptablePackets"
        $STR9 = "github.com/mattn"
        $STR10 = "github.com/fatih"
        $STR11 = "github.com/google"
        $STR12 = "github.com/satori"
        $STR13 = "github.com/!ne0nd0g"
        $STR14 = "github.com/cretz"
        $STR15 = "github.com/refraction-networking"
        $STR16 = "github.com/lucas-clemente"
        $STR17 = "github.com/marten-seemann"

    condition:

        15 of them
}

