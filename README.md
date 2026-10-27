# Coruna — Módulo de exploit iOS con re-firma de PAC

**Publicado:** 2026-10-10 · **Reporte completo:** [Desmontando Coruna](https://mihari-intelligence.blogspot.com/2026/10/desmontando-coruna-analisis-modulo-exploit-ios-bypass-pac.html) · **TLP:CLEAR**

## Resumen

Volcado de memoria que contiene un Mach-O ARM64 completo (dylib de iOS) perteneciente al exploit kit **Coruna**, documentado por Google GTIG en marzo de 2026. El módulo actúa como orquestador de la cadena: limita su ejecución a iOS 13.0 – 17.2.x, toma huella del dispositivo, comprueba el sandbox en silencio con `SANDBOX_CHECK_NO_REPORT`, detecta Corellium y, finalmente, instala un manejador de `SIGSEGV` en espacio de usuario que vuelve a firmar con PAC el contador de programa guardado del hilo. La memoria adyacente al Mach-O expone la configuración de carga, incluido un dominio de distribución sin referencias públicas a la fecha: `c2[.]token[.]info[.]pl`.

## Muestra

| Campo | Valor |
|---|---|
| Fichero | `ios-a078a8ff00923b1e9725f2c0_bufdump_20260929_111723.bin` |
| SHA-256 | `c1e0dcedab24b0bdb3278a240b00d2ac4239f1aee4d0932cbc9325000dabe021` |
| MD5 | `de155c14985463939a02a7260d3e63fc` |
| UUID Mach-O | `41d39e20-04a3-35f4-ac13-f6b200260386` |
| Formato | Mach-O 64-bit ARM (dylib) + 32 296 bytes de memoria adyacente |
| VirusTotal | 8/63 · `trojan.coruna.a` (ESET `iOS/Coruna.A`, Kaspersky `HEUR:Trojan.IphoneOS.Coruna.a`) |

## Hallazgos clave

- **Rango de versiones:** el campo `+0xC0` se compara con `0xE0000`, `0xF0000`, `0x100400` y `0x1102FF` → iOS 13.0 – 17.2.x, coherente con lo documentado por GTIG.
- **Anti-análisis:** `kern.bootargs`, `hw.l2cachesize`, `host_info(HOST_CAN_HAS_DEBUGGER)`, `/usr/libexec/corelliumd`, `IOPlatformSerialNumber`.
- **Sandbox:** `sandbox_check(pid, "iokit-open-service", SANDBOX_CHECK_NO_REPORT)` antes de tocar `IOSurfaceRoot`.
- **Selector de modo:** la cadena `MobileStore/1.0` decide si el hilo termina con `_exit(0)`; también es el User-Agent del beacon.
- **Manejador SIGSEGV:** extrae la dirección real (`& 0x7FFFFFFFFF`), verifica la firma esperada (`0x2000000000000000`) y re-firma el PC guardado; si no coincide, `abort()`.
- **Etapa siguiente (inferido):** ChaCha20 (`expand 32-byte k`) + `compression_decode_buffer` + `sys_icache_invalidate` / `sys_dcache_flush`.
- **Infraestructura:** `group.html` como página de entrega y payload `<sha1>.min.js`, mismo patrón que GTIG documentó para Coruna.

## Contenido del repositorio

| Fichero | Contenido | Validación |
|---|---|---|
| [`iocs/`](iocs) | Hashes, red, rutas, constantes. Incluye `iocs.csv`, listas por tipo (`hashes.txt`, `network.txt`, `host.txt`) y bundle STIX 2.1 | STIX validado |
| [`attack.csv`](attack.csv) | ATT&CK for Mobile | — |
| [`yara/coruna_ios.yar`](yara/coruna_ios.yar) | Módulo dylib + configuración en memoria | Compila; detecta la muestra; 0 FP sobre ~209 000 ficheros Linux. Pendiente: corpus iOS legítimo |
| [`sigma/`](sigma) | 4 reglas: proxy, DNS, User-Agent, patrón de entrega | Cargan en pySigma |
| [`suricata/coruna_ios.rules`](suricata/coruna_ios.rules) | DNS, TLS SNI, HTTP Host, User-Agent, `.min.js` | Cargan en Suricata 7.0.3; SID 1000102 (SNI) solo validado en sintaxis |

## Atribución

Familia confirmada por ESET y Kaspersky. GTIG atribuye el uso de Coruna a UNC6353 y UNC6691; Kaspersky lo relaciona con el framework de Operation Triangulation y Tencent Cloud Security con el framework Plasma. No es posible atribuir este binario concreto a un actor sin la infraestructura C2 completa.

## Referencias

- Google GTIG — [Coruna: The Mysterious Journey of a Powerful iOS Exploit Kit](https://cloud.google.com/blog/topics/threat-intelligence/coruna-powerful-ios-exploit-kit)
- Kaspersky — [Coruna como versión actualizada del framework de Operation Triangulation](https://windows.kaspersky.co.uk/about/press-releases/kaspersky-identifies-coruna-exploit-kit-as-updated-version-of-operation-triangulation-framework)
- iVerify — [Coruna: Inside the Nation-State-Grade iOS Exploit Kit](https://www.iverify.com/blog/coruna-inside-the-nation-state-grade-ios-exploit-kit-we-ve-been-tracking)

## Licencia

Reglas, IOCs y documentación bajo [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/); código bajo MIT. Ver [LICENSE](LICENSE).

---

**Mihari Threat Research** · [Blog](https://mihari-intelligence.blogspot.com/) · [mihari-intelligence.com](https://mihari-intelligence.com) · TLP:CLEAR
Este repositorio no contiene muestras de malware, solo hashes.
