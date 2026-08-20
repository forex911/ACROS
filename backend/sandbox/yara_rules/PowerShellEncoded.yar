rule PowerShellEncoded
{
    meta:
        description = "Detects encoded PowerShell execution commands"
        author = "ACROS"
        severity = "High"

    strings:
        $enc1 = "powershell -enc" ascii nocase
        $enc2 = "powershell.exe -enc" ascii nocase
        $enc3 = "powershell -EncodedCommand" ascii nocase
        $enc4 = "powershell.exe -e " ascii nocase

    condition:
        any of them
}
