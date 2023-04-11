rule GoldenTicket_GoldenSpy
{
    meta:
        author = "Duocast"
        date = "2023-04-10"
        description = "YARA rule for detecting Golden Ticket/GoldenSpy malware"

    strings:
        $reg = "Software\\IDG\\DA" nocase wide ascii // registry entry
        $str1 = "requestStr" nocase wide ascii // POST request the machine details with this parameter
        $str2 = "nb_app_log_mutex" nocase wide ascii // Mutex
        $str3 = {510F4345[0-10]50518D8DCCFE[0-20]837D1C[0-20]8D45[0-15]0F4345[0-20]505157} // Data collection and passed to requestStr in POST
        $domain1 = "www.ningzhidata[.]com" nocase wide ascii
        $domain2 = "ningzhidata[.]com" nocase wide ascii
        $ip1 = "49.232.156.177" nocase wide ascii
        $ip2 = "223.112.21.2" nocase wide ascii

    condition:
        (uint16(0) == 0x5A4D) and $reg and 2 of ($str*) and 1 of ($domain*) and 1 of ($ip*)
}
