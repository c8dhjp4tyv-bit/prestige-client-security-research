import "hash"
import "pe"

rule Prestige_Client_Exact_Captured_Samples_2026_08_16
{
    meta:
        description = "Exact hashes of Prestige Client samples analyzed on 2026-08-16"
        author = "Independent static analysis"
        date = "2026-08-16"
        confidence = "exact"
        warning = "Detection name does not assert RAT functionality"

    condition:
        uint16(0) == 0x5a4d and
        (
            hash.sha256(0, filesize) == "4507816e4942a66caa4986c5e732386aea8679f9b5253a5e17959416825e6b08" or
            hash.sha256(0, filesize) == "1472c12a4834a5b1908f1f14814ea427a7d1d43e95ec0f0a881cd0692f1aa2ad"
        )
}

rule Prestige_Injector_Controller_Family_Structural
{
    meta:
        description = "Structural detection for observed Prestige injector/controller lineage"
        author = "Independent static analysis"
        date = "2026-08-16"
        confidence = "high when endpoint, PDB and protection markers co-occur"
        warning = "Family association; not proof of RAT or credential theft"

    strings:
        $pdb = "Prestige-Injector" ascii wide
        $endpoint1 = "/injectionDownload" ascii wide
        $endpoint2 = "/injectorAccountInfo" ascii wide
        $endpoint3 = "/newFirstLogin" ascii wide
        $vmsec = ".vm_sec" ascii
        $vlizer = ".vlizer" ascii
        $ui1 = "Opening Minecraft process" ascii wide
        $ui2 = "Minecraft target" ascii wide

    condition:
        uint16(0) == 0x5a4d and
        pe.machine == pe.MACHINE_AMD64 and
        filesize > 1MB and filesize < 20MB and
        $pdb and
        3 of ($endpoint*) and
        all of ($vmsec, $vlizer) and
        1 of ($ui*)
}
