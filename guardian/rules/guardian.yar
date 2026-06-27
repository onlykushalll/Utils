/*
 * WLTIOS Guardian — YARA signature rules (production set).
 *
 * Sources: community YARA rules (YARA-Rules project) adapted + custom WLTIOS-specific.
 * Compiled with: yarac rules/guardian.yar signatures/guardian.yarc
 *
 * NOTE: hash module requires the YARA build to thread HAVE_LIBCRYPTO fully.
 * String/heuristic rules work regardless.
 */

/* ========================================================================
 *  PACKERS / PROTECTORS (malware commonly packed)
 * ======================================================================== */

rule Packed_UPX_Generic : Packer {
    meta:
        description = "UPX-packed executable"
        severity    = "low"
        author      = "guardian"
    strings:
        $upx0 = "UPX0" ascii
        $upx1 = "UPX1" ascii
        $upx_magic = { 55 50 58 21 }
    condition:
        uint16(0) == 0x5a4d and (($upx0 and $upx1) or $upx_magic)
}

rule Packed_FSG_Generic : Packer {
    meta: description = "FSG-packed executable" severity = "medium"
    strings: $m = "FSG!1.0" ascii
    condition: $m
}

rule Packed_MEW_Generic : Packer {
    meta: description = "MEW-packed executable" severity = "medium"
    strings: $m = "MEW" ascii
    condition: uint16(0) == 0x5a4d and $m
}

rule Packed_Petite_Generic : Packer {
    meta: description = "Petite-packed executable" severity = "medium"
    strings: $m = "petite" ascii nocase
    condition: $m
}

/* ========================================================================
 *  REVERSE SHELLS (high signal)
 * ======================================================================== */

rule Reverse_Shell_Bash_DevTcp : Suspicious {
    meta: description = "bash /dev/tcp reverse shell" severity = "high"
    strings:
        $a = "/dev/tcp/" ascii
        $b = "bash -i" ascii
        $c = "0<&1;0>&1" ascii
    condition: any of ($a, $b, $c)
}

rule Reverse_Shell_Python : Suspicious {
    meta: description = "python reverse shell pattern" severity = "high"
    strings:
        $a = "socket.socket" ascii
        $b = "socket.AF_INET" ascii
        $c = "os.dup2" ascii
        $d = "subprocess.call" ascii
    condition: 3 of ($a, $b, $c, $d)
}

rule Reverse_Shell_Perl : Suspicious {
    meta: description = "perl reverse shell pattern" severity = "high"
    strings:
        $a = "IO::Socket::INET" ascii
        $b = "sock->send" ascii
    condition: $a and $b
}

rule Reverse_Shell_NC : Suspicious {
    meta: description = "netcat reverse shell pattern" severity = "high"
    strings:
        $a = "nc -e /bin/sh" ascii
        $b = "ncat --exec" ascii
        $c = "mkfifo /tmp/" ascii
    condition: any of ($a, $b, $c)
}

/* ========================================================================
 *  CREDENTIAL ACCESS
 * ======================================================================== */

rule Reads_Etc_Shadow : Suspicious {
    meta: description = "binary references /etc/shadow" severity = "high"
    strings: $s = "/etc/shadow" ascii
    condition: $s
}

rule Reads_Etc_Passwd_NonRoot_Tool : Suspicious {
    meta: description = "credential tool references passwd" severity = "medium"
    strings:
        $a = "/etc/passwd" ascii
        $b = "getpwuid" ascii
    condition: $a and not $b
}

rule SSH_Key_Harvester : Suspicious {
    meta: description = "references SSH private key paths" severity = "high"
    strings:
        $a = ".ssh/id_rsa" ascii
        $b = ".ssh/id_dsa" ascii
        $c = ".ssh/id_ecdsa" ascii
        $d = ".ssh/id_ed25519" ascii
    condition: any of ($a, $b, $c, $d)
}

rule Browser_Credential_Store : Suspicious {
    meta: description = "references browser credential DBs" severity = "medium"
    strings:
        $a = "Login Data" ascii        /* Chrome */
        $b = "logins.json" ascii       /* Firefox */
        $c = "key4.db" ascii           /* Firefox */
        $d = "cookies.sqlite" ascii    /* Firefox */
    condition: 2 of ($a, $b, $c, $d)
}

/* ========================================================================
 *  PERSISTENCE MECHANISMS
 * ======================================================================== */

rule Cron_Persistence_Write : Suspicious {
    meta: description = "writes to cron (persistence)" severity = "high"
    strings:
        $a = "/etc/cron.d" ascii
        $b = "/etc/crontab" ascii
        $c = "/var/spool/cron" ascii
    condition: any of ($a, $b, $c)
}

rule Systemd_Service_Persistence : Suspicious {
    meta: description = "creates systemd service (persistence)" severity = "medium"
    strings:
        $a = "[Unit]" ascii
        $b = "[Service]" ascii
        $c = "ExecStart=" ascii
        $d = "/etc/systemd/system" ascii
    condition: $a and $b and $c and $d
}

rule Bashrc_Persistence : Suspicious {
    meta: description = "modifies bashrc (persistence)" severity = "medium"
    strings:
        $a = ".bashrc" ascii
    condition: $a
}

rule LD_Preload_Persistence : Suspicious {
    meta: description = "LD_PRELOAD hooking (persistence + rootkit)" severity = "high"
    strings:
        $a = "LD_PRELOAD" ascii
        $b = "/etc/ld.so.preload" ascii
    condition: any of ($a, $b)
}

/* ========================================================================
 *  LATERAL MOVEMENT / SCAN TOOLS
 * ======================================================================== */

rule Nmap_Scanner_Signature : Suspicious {
    meta: description = "nmap scanner binary signature" severity = "medium"
    strings:
        $a = "Nmap" ascii
        $b = "nmap.org" ascii
        $c = "NSE script" ascii
    condition: 2 of ($a, $b, $c)
}

rule Metasploit_Payload_Generic : Malware {
    meta: description = "Metasploit payload signature" severity = "critical"
    strings:
        $a = "meterpreter" ascii
        $b = "msfvenom" ascii
        $c = "Mettle" ascii
    condition: any of ($a, $b, $c)
}

rule Cobalt_Strike_Beacon : Malware {
    meta: description = "Cobalt Strike beacon signature" severity = "critical"
    strings:
        $a = "beacon.dll" ascii
        $b = "CobaltStrike" ascii
        $d = "%s is not a valid beacon" ascii
    condition: any of ($a, $b, $d)
}

/* ========================================================================
 *  CRYPTO-MINING MALWARE
 * ======================================================================== */

rule CryptoMiner_XMRig_Generic : Malware {
    meta: description = "XMRig cryptocurrency miner" severity = "high"
    strings:
        $a = "xmrig" ascii nocase
        $b = "monero" ascii nocase
        $c = "stratum+tcp" ascii
        $d = "rx/" ascii  /* RandomX algo */
    condition: 2 of ($a, $b, $c, $d)
}

rule CryptoMiner_Pool_Connection : Suspicious {
    meta: description = "connects to crypto mining pool" severity = "medium"
    strings:
        $a = "pool.minexmr" ascii
        $b = "xmr.pool.minergate" ascii
        $c = "nanopool.org" ascii
        $d = "supportxmr" ascii
    condition: any of ($a, $b, $c, $d)
}

/* ========================================================================
 *  DATA EXFILTRATION
 * ======================================================================== */

rule Exfil_To_Curl_Pipe_Bash : Suspicious {
    meta: description = "curl|bash exfil pattern" severity = "high"
    strings:
        $a = "curl" ascii
        $b = "| bash" ascii
        $c = "| sh" ascii
    condition: $a and ($b or $c)
}

rule Exfil_Wget_Pipe_Bash : Suspicious {
    meta: description = "wget|bash exfil pattern" severity = "high"
    strings:
        $a = "wget" ascii
        $b = "| bash" ascii
        $c = "| sh" ascii
    condition: $a and ($b or $c)
}

/* ========================================================================
 *  ROOTKIT INDICATORS
 * ======================================================================== */

rule LKM_Rootkit_Indicator : Suspicious {
    meta: description = "Linux kernel module rootkit indicators" severity = "critical"
    strings:
        $a = "kallsyms_lookup_name" ascii
        $b = "init_module" ascii
        $c = "module_init" ascii
        $d = "/proc/kallsyms" ascii
    condition: 2 of ($a, $b, $c, $d)
}

rule Libprocesshider : Malware {
    meta: description = "libprocesshider rootkit (LD_PRELOAD)" severity = "critical"
    strings:
        $a = "libprocesshider" ascii
        $b = "hide_pid" ascii
        $c = "replace_readdir" ascii
    condition: any of ($a, $b, $c)
}

/* ========================================================================
 *  WLTIOS-SPECIFIC THREATS (Tor-targeting)
 * ======================================================================== */

rule WLTIOS_Tor_Kill_Pattern : Suspicious {
    meta: description = "attempts to disable Tor (kill switch trigger)" severity = "critical"
    strings:
        $a = "systemctl stop tor" ascii
        $b = "killall tor" ascii
        $c = "pkill -f tor" ascii
        $d = "service tor stop" ascii
    condition: any of ($a, $b, $c, $d)
}

rule WLTIOS_Route_Add_Bypass : Suspicious {
    meta: description = "attempts to add route (bypass kill switch)" severity = "critical"
    strings:
        $a = "route add default" ascii
        $b = "ip route add" ascii
        $c = "ifconfig " ascii
    condition: any of ($a, $b, $c)
}

rule WLTIOS_Namespace_Escape_Tool : Suspicious {
    meta: description = "namespace escape tooling (unshare/nsenter)" severity = "high"
    strings:
        $a = "unshare --net" ascii
        $b = "nsenter -t" ascii
        $c = "unshare --user" ascii
    condition: any of ($a, $b, $c)
}

rule WLTIOS_Ptrace_Injector : Suspicious {
    meta: description = "ptrace-based process injector" severity = "high"
    strings:
        $a = "PTRACE_ATTACH" ascii
        $b = "PTRACE_POKETEXT" ascii
        $c = "ptrace(PTRACE_ATTACH" ascii
    condition: any of ($a, $b, $c)
}

/* ========================================================================
 *  TEST / EICAR
 * ======================================================================== */

rule EICAR_Test_File : Malware {
    meta: description = "EICAR standard antivirus test file" severity = "critical"
    strings:
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    condition: $eicar
}
