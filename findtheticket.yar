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
		
		// Strings for secondary detections
		$gs_str01 = {c78510ffffff00000000 c78514ffffff0f000000 c68500ffffff00 c78528ffffff00000000 c7852cffffff0f000000 c68518ffffff00 c78540ffffff00000000 c78544ffffff0f000000 c68530ffffff00 c645fc14 80bd04feffff00}
		$gs_str02 = "Ryeol HTTP Client Class" ascii
		$gs_str03 = "----RYEOL-FB3B405B7EAE495aB0C0295C54D4E096-" ascii
		$gs_str04 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\fwkp.exe" ascii
		$gs_str06 = "PROTOCOL_" ascii
		$gs_str07 = "softList" ascii
		$gs_str08 = "excuteExe" ascii
		
		// Strings from win_goldenspy_auto rule
        $wga_sequence_0 = { 0fb68ddffdffff 85c0 b801000000 0f44c8 8d85b0fdffff 50 8d8588feffff }
        $wga_sequence_1 = { 0f84c1010000 8b4598 b101 83f80c 7525 84c9 0f84af010000 }
        $wga_sequence_2 = { ff7304 e8???????? 83c408 85c0 0f8595000000 8bcf e8???????? }
        $wga_sequence_3 = { 7403 50 ffd6 8b4708 85c0 7410 50 }
        $wga_sequence_4 = { 8d8ddcfdffff 68???????? e8???????? 83c404 8bc8 e8???????? 8d8d14feffff }
        $wga_sequence_5 = { 8b08 8b5108 8d45e0 8b4904 4a 50 8bc6 }
        $wga_sequence_6 = { 50 6a01 57 ff15???????? 57 ffd6 5f }
        $wga_sequence_7 = { 7507 b8???????? eb39 8d858cfdffff c7858cfdffff00000000 50 8d8580fdffff }
        $wga_sequence_8 = { 2bf7 3bf0 6a00 0f47f0 8d45dc 50 }
        $wga_sequence_9 = { 8b45c4 49 8365c403 c1e802 23c8 8b4204 }

    condition:
        (uint16(0) == 0x5A4D) and (
            // Golden Ticket/GoldenSpy condition
            ($reg and 2 of ($str* or $domain or $ip)) or
            // GoldenHelper condition
            (4 of ($gh_str*)) or
            // Goldenspy_Uninstaller_v2 condition
            (4 of ($gu_str*)) or
            // Goldenspy condition
            (5 of ($gs_str*)) or
            // win_goldenspy_auto condition
            (7 of ($wga_sequence*) and filesize < 1081344)
        )
}
