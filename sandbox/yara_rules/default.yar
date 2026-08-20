rule Suspicious_Strings
{
    meta:
        description = "Detects common suspicious strings indicative of malware"
        author = "ACROS AI Baseline"
        date = "2026-06-12"
        score = 60

    strings:
        $s1 = "cmd.exe /c" nocase ascii wide
        $s2 = "powershell.exe -enc" nocase ascii wide
        $s3 = "WScript.Shell" nocase ascii wide
        $s4 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" nocase ascii wide
        $s5 = "vssadmin.exe Delete Shadows /All /Quiet" nocase ascii wide
        
        $magic1 = { 4D 5A } // MZ Header

    condition:
        ($magic1 at 0) and any of ($s*)
}
