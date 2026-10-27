/*
   Mihari Threat Research - Coruna iOS module
   Reporte: https://mihari-intelligence.blogspot.com/2026/10/desmontando-coruna-analisis-modulo-exploit-ios-bypass-pac.html
   Muestra de referencia:
     SHA-256     c1e0dcedab24b0bdb3278a240b00d2ac4239f1aee4d0932cbc9325000dabe021
     MD5         de155c14985463939a02a7260d3e63fc
     Mach-O UUID 41d39e20-04a3-35f4-ac13-f6b200260386
   TLP:CLEAR - CC BY 4.0
*/

rule MIHARI_iOS_Coruna_Module_Dylib
{
    meta:
        author      = "Mihari Threat Research"
        description = "Modulo dylib arm64 de iOS asociado al kit Coruna: fingerprinting del dispositivo, deteccion de Corellium, chequeo de sandbox y beacon HTTP con User-Agent MobileStore/1.0"
        date        = "2026-10-12"
        reference   = "https://mihari-intelligence.blogspot.com/2026/10/desmontando-coruna-analisis-modulo-exploit-ios-bypass-pac.html"
        hash        = "c1e0dcedab24b0bdb3278a240b00d2ac4239f1aee4d0932cbc9325000dabe021"
        tlp         = "CLEAR"
        confidence  = "high"

    strings:
        $ua      = "MobileStore/1.0" ascii
        $log     = "{\"cmd\":\"logmsg\",\"args\":{\"msg\":\"%s\"}}" ascii
        $evt1    = "{\\\"e\\\":%u,\\\"l\\\":%u}" ascii
        $evt2    = "{\\\"e\\\":%u,\\\"f\\\":\\\"%s\\\",\\\"l\\\":%u}" ascii
        $corell  = "/usr/libexec/corelliumd" ascii
        $xnu     = "xnu-%d.%d.%d.%d.%d%*s" ascii
        $cryptex = "/System/Cryptexes/OS/System/Library/CoreServices/SystemVersion.plist" ascii
        $ios1    = "IOSurfaceRoot" ascii
        $ios2    = "iokit-open-service" ascii
        $wc      = "WebContent" ascii
        $boot    = "kern.bootargs" ascii
        $chacha  = "expand 32-byte k" ascii
        $sbx     = "SANDBOX_CHECK_NO_REPORT" ascii

    condition:
        uint32(0) == 0xFEEDFACF                      // Mach-O 64-bit LE
        and uint32(4) == 0x0100000C                  // CPU_TYPE_ARM64
        and filesize < 2MB
        and (
            ($ua and $log and 2 of ($evt*))
            or 9 of them
        )
}

rule MIHARI_iOS_Coruna_Loader_Config_Memory
{
    meta:
        author      = "Mihari Threat Research"
        description = "Configuracion de carga Coruna en volcados de memoria o buffers: C2 c2.token.info.pl, landing group.html y payload .min.js con User-Agent de Safari iOS 15"
        date        = "2026-10-12"
        reference   = "https://mihari-intelligence.blogspot.com/2026/10/desmontando-coruna-analisis-modulo-exploit-ios-bypass-pac.html"
        hash        = "c1e0dcedab24b0bdb3278a240b00d2ac4239f1aee4d0932cbc9325000dabe021"
        tlp         = "CLEAR"
        confidence  = "medium"
        note        = "No exige cabecera Mach-O: pensada para volcados de memoria, PCAP reensamblados y artefactos de sysdiagnose"

    strings:
        $c2      = "c2.token.info.pl" ascii nocase
        $payload = /https?:\/\/[a-z0-9.\-]{4,64}\/[0-9a-f]{40}\.min\.js/ ascii
        $landing = /https?:\/\/[a-z0-9.\-]{4,64}\/group\.html/ ascii
        $ua15    = "iPhone OS 15_8_3 like Mac OS X" ascii
        $jsc     = "JSEvaluateScript" ascii

    condition:
        filesize < 50MB
        and ( $c2 or ($payload and $landing and ($ua15 or $jsc)) )
}
