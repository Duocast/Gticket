rule GoldenTicket_GoldenSpy_GoldenHelper_Uninstaller
{
    meta:
        author = "Duocast"
        date = "2023-04-10"
        description = "YARA rule for detecting Golden Ticket/GoldenSpy, GoldenHelper, and Goldenspy_Uninstaller_v2 malware"

    strings:
        // Golden Ticket/GoldenSpy strings
        $reg = "Software\\IDG\\DA" nocase wide ascii
        $str1 = "requestStr" nocase wide ascii
        $str2 = "nb_app_log_mutex" nocase wide ascii
        $str3 = {510F4345[0-10]50518D8DCCFE[0-20]837D1C[0-20]8D45[0-15]0F4345[0-20]505157}
        $domain = /(www\.)?ningzhidata(\[.\])?com/ nocase
        $ip = /(?:49\.232\.156\.177|223\.112\.21\.2)/

        // GoldenHelper strings
        $gh_str1 = "WMPAssis_AddReg" wide ascii
        $gh_str2 = "wmsma.inf" wide ascii
        $gh_str3 = "taxhelper" wide ascii
        $gh_str4 = "WMP Assistant Patch" wide ascii
        $gh_str5 = "Elevation:Administrator" wide ascii

        // Goldenspy_Uninstaller_v2 strings
        $gu_str1 = "taskkill /IM svm.exe /IM svmm.exe /F" ascii
        $gu_str2 = "\\svm.exe -stopProtect" ascii
        $gu_str3 = "\\svmm.exe -u" ascii
        $gu_str4 = "\\VCProject\\dgs\\Release\\" ascii
        $gu_str5 = "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\svm" ascii
        $gu_str6 = "\\svmm.exe -stopProtect" ascii
        $gu_str7 = "\\svm.exe -u" ascii
        $gu_str8 = "Software\\Microsoft\\Windows\\CurrentVersion\\App Paths\\svm.exe" ascii
        $gu_str9 = "dGFza2tpbGwgL0lNIHN2bS5leGUgL0lNIHN2bW0uZXhlIC9GIA" ascii
        $gu_str10 = "c3ZtLmV4ZSAtc3RvcFByb3RlY3Q" ascii
        $gu_str11 = "XHN2bW0uZXhlIC11" ascii
        $gu_str12 = "U29mdHdhcmVcTWljcm9zb2Z0XFdpbmRvd3NcQ3VycmVudFZlcnNpb25cVW5pbnN0YWxsXHN2bQ" ascii
        $gu_str13 = "U29mdHdhcmVcTWljcm9zb2Z0XFdpbmRvd3NcQ3VycmVudFZlcnNpb25cQXBwIFBhdGhzXHN2bS5leGU" ascii
        $gu_str14 = "XHN2bS5leGUgLXU" ascii
        $gu_str15 = "c3ZtbS5leGUgLXN0b3BQcm90ZWN0" ascii

    condition:
        (uint16(0) == 0x5A4D) and (
            // Golden Ticket/GoldenSpy condition
            ($reg and 2 of ($str* or $domain or $ip)) or
            // GoldenHelper condition
            (4 of ($gh_str*)) or
            // Goldenspy_Uninstaller_v2 condition
            (4 of ($gu_str*))
        )
}
