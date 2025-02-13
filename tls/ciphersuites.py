#!/usr/bin/python

# Cipher suites
TLS_NULL_WITH_NULL_NULL = 0x0000
TLS_RSA_WITH_NULL_MD5 = 0x0001
TLS_RSA_WITH_NULL_SHA = 0x0002
TLS_RSA_EXPORT_WITH_RC4_40_MD5 = 0x0003
TLS_RSA_WITH_RC4_128_MD5 = 0x0004
TLS_RSA_WITH_RC4_128_SHA = 0x0005
TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5 = 0x0006
TLS_RSA_WITH_IDEA_CBC_SHA = 0x0007
TLS_RSA_EXPORT_WITH_DES40_CBC_SHA = 0x0008
TLS_RSA_WITH_DES_CBC_SHA = 0x0009
TLS_RSA_WITH_3DES_EDE_CBC_SHA = 0x000A
TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA = 0x000B
TLS_DH_DSS_WITH_DES_CBC_SHA = 0x000C
TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA = 0x000D
TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA = 0x000E
TLS_DH_RSA_WITH_DES_CBC_SHA = 0x000F
TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA = 0x0010
TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA = 0x0011
TLS_DHE_DSS_WITH_DES_CBC_SHA = 0x0012
TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA = 0x0013
TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA = 0x0014
TLS_DHE_RSA_WITH_DES_CBC_SHA = 0x0015
TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA = 0x0016
TLS_DH_anon_EXPORT_WITH_RC4_40_MD5 = 0x0017
TLS_DH_anon_WITH_RC4_128_MD5 = 0x0018
TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA = 0x0019
TLS_DH_anon_WITH_DES_CBC_SHA = 0x001A
TLS_DH_anon_WITH_3DES_EDE_CBC_SHA = 0x001B
TLS_KRB5_WITH_DES_CBC_SHA = 0x001E
TLS_KRB5_WITH_3DES_EDE_CBC_SHA = 0x001F
TLS_KRB5_WITH_RC4_128_SHA = 0x0020
TLS_KRB5_WITH_IDEA_CBC_SHA = 0x0021
TLS_KRB5_WITH_DES_CBC_MD5 = 0x0022
TLS_KRB5_WITH_3DES_EDE_CBC_MD5 = 0x0023
TLS_KRB5_WITH_RC4_128_MD5 = 0x0024
TLS_KRB5_WITH_IDEA_CBC_MD5 = 0x0025
TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA = 0x0026
TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA = 0x0027
TLS_KRB5_EXPORT_WITH_RC4_40_SHA = 0x0028
TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5 = 0x0029
TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5 = 0x002A
TLS_KRB5_EXPORT_WITH_RC4_40_MD5 = 0x002B
TLS_PSK_WITH_NULL_SHA = 0x002C
TLS_DHE_PSK_WITH_NULL_SHA = 0x002D
TLS_RSA_PSK_WITH_NULL_SHA = 0x002E
TLS_RSA_WITH_AES_128_CBC_SHA = 0x002F
TLS_DH_DSS_WITH_AES_128_CBC_SHA = 0x0030
TLS_DH_RSA_WITH_AES_128_CBC_SHA = 0x0031
TLS_DHE_DSS_WITH_AES_128_CBC_SHA = 0x0032
TLS_DHE_RSA_WITH_AES_128_CBC_SHA = 0x0033
TLS_DH_anon_WITH_AES_128_CBC_SHA = 0x0034
TLS_RSA_WITH_AES_256_CBC_SHA = 0x0035
TLS_DH_DSS_WITH_AES_256_CBC_SHA = 0x0036
TLS_DH_RSA_WITH_AES_256_CBC_SHA = 0x0037
TLS_DHE_DSS_WITH_AES_256_CBC_SHA = 0x0038
TLS_DHE_RSA_WITH_AES_256_CBC_SHA = 0x0039
TLS_DH_anon_WITH_AES_256_CBC_SHA = 0x003A
TLS_RSA_WITH_NULL_SHA256 = 0x003B
TLS_RSA_WITH_AES_128_CBC_SHA256 = 0x003C
TLS_RSA_WITH_AES_256_CBC_SHA256 = 0x003D
TLS_DH_DSS_WITH_AES_128_CBC_SHA256 = 0x003E
TLS_DH_RSA_WITH_AES_128_CBC_SHA256 = 0x003F
TLS_DHE_DSS_WITH_AES_128_CBC_SHA256 = 0x0040
TLS_RSA_WITH_CAMELLIA_128_CBC_SHA = 0x0041
TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA = 0x0042
TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA = 0x0043
TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA = 0x0044
TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA = 0x0045
TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA = 0x0046
TLS_DHE_RSA_WITH_AES_128_CBC_SHA256 = 0x0067
TLS_DH_DSS_WITH_AES_256_CBC_SHA256 = 0x0068
TLS_DH_RSA_WITH_AES_256_CBC_SHA256 = 0x0069
TLS_DHE_DSS_WITH_AES_256_CBC_SHA256 = 0x006A
TLS_DHE_RSA_WITH_AES_256_CBC_SHA256 = 0x006B
TLS_DH_anon_WITH_AES_128_CBC_SHA256 = 0x006C
TLS_DH_anon_WITH_AES_256_CBC_SHA256 = 0x006D
TLS_RSA_WITH_CAMELLIA_256_CBC_SHA = 0x0084
TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA = 0x0085
TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA = 0x0086
TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA = 0x0087
TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA = 0x0088
TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA = 0x0089
TLS_PSK_WITH_RC4_128_SHA = 0x008A
TLS_PSK_WITH_3DES_EDE_CBC_SHA = 0x008B
TLS_PSK_WITH_AES_128_CBC_SHA = 0x008C
TLS_PSK_WITH_AES_256_CBC_SHA = 0x008D
TLS_DHE_PSK_WITH_RC4_128_SHA = 0x008E
TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA = 0x008F
TLS_DHE_PSK_WITH_AES_128_CBC_SHA = 0x0090
TLS_DHE_PSK_WITH_AES_256_CBC_SHA = 0x0091
TLS_RSA_PSK_WITH_RC4_128_SHA = 0x0092
TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA = 0x0093
TLS_RSA_PSK_WITH_AES_128_CBC_SHA = 0x0094
TLS_RSA_PSK_WITH_AES_256_CBC_SHA = 0x0095
TLS_RSA_WITH_SEED_CBC_SHA = 0x0096
TLS_DH_DSS_WITH_SEED_CBC_SHA = 0x0097
TLS_DH_RSA_WITH_SEED_CBC_SHA = 0x0098
TLS_DHE_DSS_WITH_SEED_CBC_SHA = 0x0099
TLS_DHE_RSA_WITH_SEED_CBC_SHA = 0x009A
TLS_DH_anon_WITH_SEED_CBC_SHA = 0x009B
TLS_RSA_WITH_AES_128_GCM_SHA256 = 0x009C
TLS_RSA_WITH_AES_256_GCM_SHA384 = 0x009D
TLS_DHE_RSA_WITH_AES_128_GCM_SHA256 = 0x009E
TLS_DHE_RSA_WITH_AES_256_GCM_SHA384 = 0x009F
TLS_DH_RSA_WITH_AES_128_GCM_SHA256 = 0x00A0
TLS_DH_RSA_WITH_AES_256_GCM_SHA384 = 0x00A1
TLS_DHE_DSS_WITH_AES_128_GCM_SHA256 = 0x00A2
TLS_DHE_DSS_WITH_AES_256_GCM_SHA384 = 0x00A3
TLS_DH_DSS_WITH_AES_128_GCM_SHA256 = 0x00A4
TLS_DH_DSS_WITH_AES_256_GCM_SHA384 = 0x00A5
TLS_DH_anon_WITH_AES_128_GCM_SHA256 = 0x00A6
TLS_DH_anon_WITH_AES_256_GCM_SHA384 = 0x00A7
TLS_PSK_WITH_AES_128_GCM_SHA256 = 0x00A8
TLS_PSK_WITH_AES_256_GCM_SHA384 = 0x00A9
TLS_DHE_PSK_WITH_AES_128_GCM_SHA256 = 0x00AA
TLS_DHE_PSK_WITH_AES_256_GCM_SHA384 = 0x00AB
TLS_RSA_PSK_WITH_AES_128_GCM_SHA256 = 0x00AC
TLS_RSA_PSK_WITH_AES_256_GCM_SHA384 = 0x00AD
TLS_PSK_WITH_AES_128_CBC_SHA256 = 0x00AE
TLS_PSK_WITH_AES_256_CBC_SHA384 = 0x00AF
TLS_PSK_WITH_NULL_SHA256 = 0x00B0
TLS_PSK_WITH_NULL_SHA384 = 0x00B1
TLS_DHE_PSK_WITH_AES_128_CBC_SHA256 = 0x00B2
TLS_DHE_PSK_WITH_AES_256_CBC_SHA384 = 0x00B3
TLS_DHE_PSK_WITH_NULL_SHA256 = 0x00B4
TLS_DHE_PSK_WITH_NULL_SHA384 = 0x00B5
TLS_RSA_PSK_WITH_AES_128_CBC_SHA256 = 0x00B6
TLS_RSA_PSK_WITH_AES_256_CBC_SHA384 = 0x00B7
TLS_RSA_PSK_WITH_NULL_SHA256 = 0x00B8
TLS_RSA_PSK_WITH_NULL_SHA384 = 0x00B9
TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256 = 0x00BA
TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256 = 0x00BB
TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256 = 0x00BC
TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256 = 0x00BD
TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256 = 0x00BE
TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256 = 0x00BF
TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256 = 0x00C0
TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256 = 0x00C1
TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256 = 0x00C2
TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256 = 0x00C3
TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256 = 0x00C4
TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256 = 0x00C5
TLS_EMPTY_RENEGOTIATION_INFO_SCSV = 0x00FF
TLS_ECDH_ECDSA_WITH_NULL_SHA = 0xC001
TLS_ECDH_ECDSA_WITH_RC4_128_SHA = 0xC002
TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA = 0xC003
TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA = 0xC004
TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA = 0xC005
TLS_ECDHE_ECDSA_WITH_NULL_SHA = 0xC006
TLS_ECDHE_ECDSA_WITH_RC4_128_SHA = 0xC007
TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA = 0xC008
TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA = 0xC009
TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA = 0xC00A
TLS_ECDH_RSA_WITH_NULL_SHA = 0xC00B
TLS_ECDH_RSA_WITH_RC4_128_SHA = 0xC00C
TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA = 0xC00D
TLS_ECDH_RSA_WITH_AES_128_CBC_SHA = 0xC00E
TLS_ECDH_RSA_WITH_AES_256_CBC_SHA = 0xC00F
TLS_ECDHE_RSA_WITH_NULL_SHA = 0xC010
TLS_ECDHE_RSA_WITH_RC4_128_SHA = 0xC011
TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA = 0xC012
TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA = 0xC013
TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA = 0xC014
TLS_ECDH_anon_WITH_NULL_SHA = 0xC015
TLS_ECDH_anon_WITH_RC4_128_SHA = 0xC016
TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA = 0xC017
TLS_ECDH_anon_WITH_AES_128_CBC_SHA = 0xC018
TLS_ECDH_anon_WITH_AES_256_CBC_SHA = 0xC019
TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA = 0xC01A
TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA = 0xC01B
TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA = 0xC01C
TLS_SRP_SHA_WITH_AES_128_CBC_SHA = 0xC01D
TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA = 0xC01E
TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA = 0xC01F
TLS_SRP_SHA_WITH_AES_256_CBC_SHA = 0xC020
TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA = 0xC021
TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA = 0xC022
TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 = 0xC023
TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384 = 0xC024
TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256 = 0xC025
TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384 = 0xC026
TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256 = 0xC027
TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384 = 0xC028
TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256 = 0xC029
TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384 = 0xC02A
TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 = 0xC02B
TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 = 0xC02C
TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256 = 0xC02D
TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384 = 0xC02E
TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 = 0xC02F
TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 = 0xC030
TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256 = 0xC031
TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384 = 0xC032
TLS_ECDHE_PSK_WITH_RC4_128_SHA = 0xC033
TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA = 0xC034
TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA = 0xC035
TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA = 0xC036
TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256 = 0xC037
TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384 = 0xC038
TLS_ECDHE_PSK_WITH_NULL_SHA = 0xC039
TLS_ECDHE_PSK_WITH_NULL_SHA256 = 0xC03A
TLS_ECDHE_PSK_WITH_NULL_SHA384 = 0xC03B
TLS_RSA_WITH_ARIA_128_CBC_SHA256 = 0xC03C
TLS_RSA_WITH_ARIA_256_CBC_SHA384 = 0xC03D
TLS_DH_DSS_WITH_ARIA_128_CBC_SHA256 = 0xC03E
TLS_DH_DSS_WITH_ARIA_256_CBC_SHA384 = 0xC03F
TLS_DH_RSA_WITH_ARIA_128_CBC_SHA256 = 0xC040
TLS_DH_RSA_WITH_ARIA_256_CBC_SHA384 = 0xC041
TLS_DHE_DSS_WITH_ARIA_128_CBC_SHA256 = 0xC042
TLS_DHE_DSS_WITH_ARIA_256_CBC_SHA384 = 0xC043
TLS_DHE_RSA_WITH_ARIA_128_CBC_SHA256 = 0xC044
TLS_DHE_RSA_WITH_ARIA_256_CBC_SHA384 = 0xC045
TLS_DH_anon_WITH_ARIA_128_CBC_SHA256 = 0xC046
TLS_DH_anon_WITH_ARIA_256_CBC_SHA384 = 0xC047
TLS_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256 = 0xC048
TLS_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384 = 0xC049
TLS_ECDH_ECDSA_WITH_ARIA_128_CBC_SHA256 = 0xC04A
TLS_ECDH_ECDSA_WITH_ARIA_256_CBC_SHA384 = 0xC04B
TLS_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256 = 0xC04C
TLS_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384 = 0xC04D
TLS_ECDH_RSA_WITH_ARIA_128_CBC_SHA256 = 0xC04E
TLS_ECDH_RSA_WITH_ARIA_256_CBC_SHA384 = 0xC04F
TLS_RSA_WITH_ARIA_128_GCM_SHA256 = 0xC050
TLS_RSA_WITH_ARIA_256_GCM_SHA384 = 0xC051
TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256 = 0xC052
TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384 = 0xC053
TLS_DH_RSA_WITH_ARIA_128_GCM_SHA256 = 0xC054
TLS_DH_RSA_WITH_ARIA_256_GCM_SHA384 = 0xC055
TLS_DHE_DSS_WITH_ARIA_128_GCM_SHA256 = 0xC056
TLS_DHE_DSS_WITH_ARIA_256_GCM_SHA384 = 0xC057
TLS_DH_DSS_WITH_ARIA_128_GCM_SHA256 = 0xC058
TLS_DH_DSS_WITH_ARIA_256_GCM_SHA384 = 0xC059
TLS_DH_anon_WITH_ARIA_128_GCM_SHA256 = 0xC05A
TLS_DH_anon_WITH_ARIA_256_GCM_SHA384 = 0xC05B
TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256 = 0xC05C
TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384 = 0xC05D
TLS_ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256 = 0xC05E
TLS_ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384 = 0xC05F
TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256 = 0xC060
TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384 = 0xC061
TLS_ECDH_RSA_WITH_ARIA_128_GCM_SHA256 = 0xC062
TLS_ECDH_RSA_WITH_ARIA_256_GCM_SHA384 = 0xC063
TLS_PSK_WITH_ARIA_128_CBC_SHA256 = 0xC064
TLS_PSK_WITH_ARIA_256_CBC_SHA384 = 0xC065
TLS_DHE_PSK_WITH_ARIA_128_CBC_SHA256 = 0xC066
TLS_DHE_PSK_WITH_ARIA_256_CBC_SHA384 = 0xC067
TLS_RSA_PSK_WITH_ARIA_128_CBC_SHA256 = 0xC068
TLS_RSA_PSK_WITH_ARIA_256_CBC_SHA384 = 0xC069
TLS_PSK_WITH_ARIA_128_GCM_SHA256 = 0xC06A
TLS_PSK_WITH_ARIA_256_GCM_SHA384 = 0xC06B
TLS_DHE_PSK_WITH_ARIA_128_GCM_SHA256 = 0xC06C
TLS_DHE_PSK_WITH_ARIA_256_GCM_SHA384 = 0xC06D
TLS_RSA_PSK_WITH_ARIA_128_GCM_SHA256 = 0xC06E
TLS_RSA_PSK_WITH_ARIA_256_GCM_SHA384 = 0xC06F
TLS_ECDHE_PSK_WITH_ARIA_128_CBC_SHA256 = 0xC070
TLS_ECDHE_PSK_WITH_ARIA_256_CBC_SHA384 = 0xC071
TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256 = 0xC072
TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384 = 0xC073
TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256 = 0xC074
TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384 = 0xC075
TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256 = 0xC076
TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384 = 0xC077
TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256 = 0xC078
TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384 = 0xC079
TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256 = 0xC07A
TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384 = 0xC07B
TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256 = 0xC07C
TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384 = 0xC07D
TLS_DH_RSA_WITH_CAMELLIA_128_GCM_SHA256 = 0xC07E
TLS_DH_RSA_WITH_CAMELLIA_256_GCM_SHA384 = 0xC07F
TLS_DHE_DSS_WITH_CAMELLIA_128_GCM_SHA256 = 0xC080
TLS_DHE_DSS_WITH_CAMELLIA_256_GCM_SHA384 = 0xC081
TLS_DH_DSS_WITH_CAMELLIA_128_GCM_SHA256 = 0xC082
TLS_DH_DSS_WITH_CAMELLIA_256_GCM_SHA384 = 0xC083
TLS_DH_anon_WITH_CAMELLIA_128_GCM_SHA256 = 0xC084
TLS_DH_anon_WITH_CAMELLIA_256_GCM_SHA384 = 0xC085
TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256 = 0xC086
TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384 = 0xC087
TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256 = 0xC088
TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384 = 0xC089
TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256 = 0xC08A
TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384 = 0xC08B
TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256 = 0xC08C
TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384 = 0xC08D
TLS_PSK_WITH_CAMELLIA_128_GCM_SHA256 = 0xC08E
TLS_PSK_WITH_CAMELLIA_256_GCM_SHA384 = 0xC08F
TLS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256 = 0xC090
TLS_DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384 = 0xC091
TLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256 = 0xC092
TLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384 = 0xC093
TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256 = 0xC094
TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384 = 0xC095
TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256 = 0xC096
TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384 = 0xC097
TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256 = 0xC098
TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384 = 0xC099
TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256 = 0xC09A
TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384 = 0xC09B
TLS_RSA_WITH_AES_128_CCM = 0xC09C
TLS_RSA_WITH_AES_256_CCM = 0xC09D
TLS_DHE_RSA_WITH_AES_128_CCM = 0xC09E
TLS_DHE_RSA_WITH_AES_256_CCM = 0xC09F
TLS_RSA_WITH_AES_128_CCM_8 = 0xC0A0
TLS_RSA_WITH_AES_256_CCM_8 = 0xC0A1
TLS_DHE_RSA_WITH_AES_128_CCM_8 = 0xC0A2
TLS_DHE_RSA_WITH_AES_256_CCM_8 = 0xC0A3
TLS_PSK_WITH_AES_128_CCM = 0xC0A4
TLS_PSK_WITH_AES_256_CCM = 0xC0A5
TLS_DHE_PSK_WITH_AES_128_CCM = 0xC0A6
TLS_DHE_PSK_WITH_AES_256_CCM = 0xC0A7
TLS_PSK_WITH_AES_128_CCM_8 = 0xC0A8
TLS_PSK_WITH_AES_256_CCM_8 = 0xC0A9
TLS_PSK_DHE_WITH_AES_128_CCM_8 = 0xC0AA
TLS_PSK_DHE_WITH_AES_256_CCM_8 = 0xC0AB
TLS_ECDHE_ECDSA_WITH_AES_128_CCM = 0xC0AC
TLS_ECDHE_ECDSA_WITH_AES_256_CCM = 0xC0AD
TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8 = 0xC0AE
TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8 = 0xC0AF

# Experimental
TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305 = 0xCC13
TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305 = 0xCC14
TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256 = 0xCC15

# Special
TLS_FALLBACK_SCSV = 0x5600
TLS_EMPTY_RENEGOTIATION_INFO_SCSV = 0xFF00

cipher_suites = {
    0x0: "TLS_NULL_WITH_NULL_NULL",
    0x1: "TLS_RSA_WITH_NULL_MD5",
    0x2: "TLS_RSA_WITH_NULL_SHA",
    0x3: "TLS_RSA_EXPORT_WITH_RC4_40_MD5",
    0x4: "TLS_RSA_WITH_RC4_128_MD5",
    0x5: "TLS_RSA_WITH_RC4_128_SHA",
    0x6: "TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5",
    0x7: "TLS_RSA_WITH_IDEA_CBC_SHA",
    0x8: "TLS_RSA_EXPORT_WITH_DES40_CBC_SHA",
    0x9: "TLS_RSA_WITH_DES_CBC_SHA",
    0xA: "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
    0xB: "TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA",
    0xC: "TLS_DH_DSS_WITH_DES_CBC_SHA",
    0xD: "TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA",
    0xE: "TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA",
    0xF: "TLS_DH_RSA_WITH_DES_CBC_SHA",
    0x10: "TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA",
    0x11: "TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA",
    0x12: "TLS_DHE_DSS_WITH_DES_CBC_SHA",
    0x13: "TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA",
    0x14: "TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA",
    0x15: "TLS_DHE_RSA_WITH_DES_CBC_SHA",
    0x16: "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA",
    0x17: "TLS_DH_anon_EXPORT_WITH_RC4_40_MD5",
    0x18: "TLS_DH_anon_WITH_RC4_128_MD5",
    0x19: "TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA",
    0x1A: "TLS_DH_anon_WITH_DES_CBC_SHA",
    0x1B: "TLS_DH_anon_WITH_3DES_EDE_CBC_SHA",
    0x1E: "TLS_KRB5_WITH_DES_CBC_SHA",
    0x1F: "TLS_KRB5_WITH_3DES_EDE_CBC_SHA",
    0x20: "TLS_KRB5_WITH_RC4_128_SHA",
    0x21: "TLS_KRB5_WITH_IDEA_CBC_SHA",
    0x22: "TLS_KRB5_WITH_DES_CBC_MD5",
    0x23: "TLS_KRB5_WITH_3DES_EDE_CBC_MD5",
    0x24: "TLS_KRB5_WITH_RC4_128_MD5",
    0x25: "TLS_KRB5_WITH_IDEA_CBC_MD5",
    0x26: "TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA",
    0x27: "TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA",
    0x28: "TLS_KRB5_EXPORT_WITH_RC4_40_SHA",
    0x29: "TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5",
    0x2A: "TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5",
    0x2B: "TLS_KRB5_EXPORT_WITH_RC4_40_MD5",
    0x2C: "TLS_PSK_WITH_NULL_SHA",
    0x2D: "TLS_DHE_PSK_WITH_NULL_SHA",
    0x2E: "TLS_RSA_PSK_WITH_NULL_SHA",
    0x2F: "TLS_RSA_WITH_AES_128_CBC_SHA",
    0x30: "TLS_DH_DSS_WITH_AES_128_CBC_SHA",
    0x31: "TLS_DH_RSA_WITH_AES_128_CBC_SHA",
    0x32: "TLS_DHE_DSS_WITH_AES_128_CBC_SHA",
    0x33: "TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
    0x34: "TLS_DH_anon_WITH_AES_128_CBC_SHA",
    0x35: "TLS_RSA_WITH_AES_256_CBC_SHA",
    0x36: "TLS_DH_DSS_WITH_AES_256_CBC_SHA",
    0x37: "TLS_DH_RSA_WITH_AES_256_CBC_SHA",
    0x38: "TLS_DHE_DSS_WITH_AES_256_CBC_SHA",
    0x39: "TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
    0x3A: "TLS_DH_anon_WITH_AES_256_CBC_SHA",
    0x3B: "TLS_RSA_WITH_NULL_SHA256",
    0x3C: "TLS_RSA_WITH_AES_128_CBC_SHA256",
    0x3D: "TLS_RSA_WITH_AES_256_CBC_SHA256",
    0x3E: "TLS_DH_DSS_WITH_AES_128_CBC_SHA256",
    0x3F: "TLS_DH_RSA_WITH_AES_128_CBC_SHA256",
    0x40: "TLS_DHE_DSS_WITH_AES_128_CBC_SHA256",
    0x41: "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA",
    0x42: "TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA",
    0x43: "TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA",
    0x44: "TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA",
    0x45: "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA",
    0x46: "TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA",
    0x67: "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256",
    0x68: "TLS_DH_DSS_WITH_AES_256_CBC_SHA256",
    0x69: "TLS_DH_RSA_WITH_AES_256_CBC_SHA256",
    0x6A: "TLS_DHE_DSS_WITH_AES_256_CBC_SHA256",
    0x6B: "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256",
    0x6C: "TLS_DH_anon_WITH_AES_128_CBC_SHA256",
    0x6D: "TLS_DH_anon_WITH_AES_256_CBC_SHA256",
    0x84: "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA",
    0x85: "TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA",
    0x86: "TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA",
    0x87: "TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA",
    0x88: "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA",
    0x89: "TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA",
    0x8A: "TLS_PSK_WITH_RC4_128_SHA",
    0x8B: "TLS_PSK_WITH_3DES_EDE_CBC_SHA",
    0x8C: "TLS_PSK_WITH_AES_128_CBC_SHA",
    0x8D: "TLS_PSK_WITH_AES_256_CBC_SHA",
    0x8E: "TLS_DHE_PSK_WITH_RC4_128_SHA",
    0x8F: "TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA",
    0x90: "TLS_DHE_PSK_WITH_AES_128_CBC_SHA",
    0x91: "TLS_DHE_PSK_WITH_AES_256_CBC_SHA",
    0x92: "TLS_RSA_PSK_WITH_RC4_128_SHA",
    0x93: "TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA",
    0x94: "TLS_RSA_PSK_WITH_AES_128_CBC_SHA",
    0x95: "TLS_RSA_PSK_WITH_AES_256_CBC_SHA",
    0x96: "TLS_RSA_WITH_SEED_CBC_SHA",
    0x97: "TLS_DH_DSS_WITH_SEED_CBC_SHA",
    0x98: "TLS_DH_RSA_WITH_SEED_CBC_SHA",
    0x99: "TLS_DHE_DSS_WITH_SEED_CBC_SHA",
    0x9A: "TLS_DHE_RSA_WITH_SEED_CBC_SHA",
    0x9B: "TLS_DH_anon_WITH_SEED_CBC_SHA",
    0x9C: "TLS_RSA_WITH_AES_128_GCM_SHA256",
    0x9D: "TLS_RSA_WITH_AES_256_GCM_SHA384",
    0x9E: "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
    0x9F: "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
    0xA0: "TLS_DH_RSA_WITH_AES_128_GCM_SHA256",
    0xA1: "TLS_DH_RSA_WITH_AES_256_GCM_SHA384",
    0xA2: "TLS_DHE_DSS_WITH_AES_128_GCM_SHA256",
    0xA3: "TLS_DHE_DSS_WITH_AES_256_GCM_SHA384",
    0xA4: "TLS_DH_DSS_WITH_AES_128_GCM_SHA256",
    0xA5: "TLS_DH_DSS_WITH_AES_256_GCM_SHA384",
    0xA6: "TLS_DH_anon_WITH_AES_128_GCM_SHA256",
    0xA7: "TLS_DH_anon_WITH_AES_256_GCM_SHA384",
    0xA8: "TLS_PSK_WITH_AES_128_GCM_SHA256",
    0xA9: "TLS_PSK_WITH_AES_256_GCM_SHA384",
    0xAA: "TLS_DHE_PSK_WITH_AES_128_GCM_SHA256",
    0xAB: "TLS_DHE_PSK_WITH_AES_256_GCM_SHA384",
    0xAC: "TLS_RSA_PSK_WITH_AES_128_GCM_SHA256",
    0xAD: "TLS_RSA_PSK_WITH_AES_256_GCM_SHA384",
    0xAE: "TLS_PSK_WITH_AES_128_CBC_SHA256",
    0xAF: "TLS_PSK_WITH_AES_256_CBC_SHA384",
    0xB0: "TLS_PSK_WITH_NULL_SHA256",
    0xB1: "TLS_PSK_WITH_NULL_SHA384",
    0xB2: "TLS_DHE_PSK_WITH_AES_128_CBC_SHA256",
    0xB3: "TLS_DHE_PSK_WITH_AES_256_CBC_SHA384",
    0xB4: "TLS_DHE_PSK_WITH_NULL_SHA256",
    0xB5: "TLS_DHE_PSK_WITH_NULL_SHA384",
    0xB6: "TLS_RSA_PSK_WITH_AES_128_CBC_SHA256",
    0xB7: "TLS_RSA_PSK_WITH_AES_256_CBC_SHA384",
    0xB8: "TLS_RSA_PSK_WITH_NULL_SHA256",
    0xB9: "TLS_RSA_PSK_WITH_NULL_SHA384",
    0xBA: "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256",
    0xBB: "TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256",
    0xBC: "TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256",
    0xBD: "TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256",
    0xBE: "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256",
    0xBF: "TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256",
    0xC0: "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256",
    0xC1: "TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256",
    0xC2: "TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256",
    0xC3: "TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256",
    0xC4: "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256",
    0xC5: "TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256",
    0xFF: "TLS_EMPTY_RENEGOTIATION_INFO_SCSV",
    0xC001: "TLS_ECDH_ECDSA_WITH_NULL_SHA",
    0xC002: "TLS_ECDH_ECDSA_WITH_RC4_128_SHA",
    0xC003: "TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA",
    0xC004: "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA",
    0xC005: "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA",
    0xC006: "TLS_ECDHE_ECDSA_WITH_NULL_SHA",
    0xC007: "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA",
    0xC008: "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA",
    0xC009: "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
    0xC00A: "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
    0xC00B: "TLS_ECDH_RSA_WITH_NULL_SHA",
    0xC00C: "TLS_ECDH_RSA_WITH_RC4_128_SHA",
    0xC00D: "TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA",
    0xC00E: "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA",
    0xC00F: "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA",
    0xC010: "TLS_ECDHE_RSA_WITH_NULL_SHA",
    0xC011: "TLS_ECDHE_RSA_WITH_RC4_128_SHA",
    0xC012: "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA",
    0xC013: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
    0xC014: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
    0xC015: "TLS_ECDH_anon_WITH_NULL_SHA",
    0xC016: "TLS_ECDH_anon_WITH_RC4_128_SHA",
    0xC017: "TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA",
    0xC018: "TLS_ECDH_anon_WITH_AES_128_CBC_SHA",
    0xC019: "TLS_ECDH_anon_WITH_AES_256_CBC_SHA",
    0xC01A: "TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA",
    0xC01B: "TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA",
    0xC01C: "TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA",
    0xC01D: "TLS_SRP_SHA_WITH_AES_128_CBC_SHA",
    0xC01E: "TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA",
    0xC01F: "TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA",
    0xC020: "TLS_SRP_SHA_WITH_AES_256_CBC_SHA",
    0xC021: "TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA",
    0xC022: "TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA",
    0xC023: "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
    0xC024: "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
    0xC025: "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256",
    0xC026: "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384",
    0xC027: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
    0xC028: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
    0xC029: "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256",
    0xC02A: "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384",
    0xC02B: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    0xC02C: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    0xC02D: "TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256",
    0xC02E: "TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384",
    0xC02F: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    0xC030: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    0xC031: "TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256",
    0xC032: "TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384",
    0xC033: "TLS_ECDHE_PSK_WITH_RC4_128_SHA",
    0xC034: "TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA",
    0xC035: "TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA",
    0xC036: "TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA",
    0xC037: "TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256",
    0xC038: "TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384",
    0xC039: "TLS_ECDHE_PSK_WITH_NULL_SHA",
    0xC03A: "TLS_ECDHE_PSK_WITH_NULL_SHA256",
    0xC03B: "TLS_ECDHE_PSK_WITH_NULL_SHA384",
    0xC03C: "TLS_RSA_WITH_ARIA_128_CBC_SHA256",
    0xC03D: "TLS_RSA_WITH_ARIA_256_CBC_SHA384",
    0xC03E: "TLS_DH_DSS_WITH_ARIA_128_CBC_SHA256",
    0xC03F: "TLS_DH_DSS_WITH_ARIA_256_CBC_SHA384",
    0xC040: "TLS_DH_RSA_WITH_ARIA_128_CBC_SHA256",
    0xC041: "TLS_DH_RSA_WITH_ARIA_256_CBC_SHA384",
    0xC042: "TLS_DHE_DSS_WITH_ARIA_128_CBC_SHA256",
    0xC043: "TLS_DHE_DSS_WITH_ARIA_256_CBC_SHA384",
    0xC044: "TLS_DHE_RSA_WITH_ARIA_128_CBC_SHA256",
    0xC045: "TLS_DHE_RSA_WITH_ARIA_256_CBC_SHA384",
    0xC046: "TLS_DH_anon_WITH_ARIA_128_CBC_SHA256",
    0xC047: "TLS_DH_anon_WITH_ARIA_256_CBC_SHA384",
    0xC048: "TLS_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256",
    0xC049: "TLS_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384",
    0xC04A: "TLS_ECDH_ECDSA_WITH_ARIA_128_CBC_SHA256",
    0xC04B: "TLS_ECDH_ECDSA_WITH_ARIA_256_CBC_SHA384",
    0xC04C: "TLS_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256",
    0xC04D: "TLS_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384",
    0xC04E: "TLS_ECDH_RSA_WITH_ARIA_128_CBC_SHA256",
    0xC04F: "TLS_ECDH_RSA_WITH_ARIA_256_CBC_SHA384",
    0xC050: "TLS_RSA_WITH_ARIA_128_GCM_SHA256",
    0xC051: "TLS_RSA_WITH_ARIA_256_GCM_SHA384",
    0xC052: "TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256",
    0xC053: "TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384",
    0xC054: "TLS_DH_RSA_WITH_ARIA_128_GCM_SHA256",
    0xC055: "TLS_DH_RSA_WITH_ARIA_256_GCM_SHA384",
    0xC056: "TLS_DHE_DSS_WITH_ARIA_128_GCM_SHA256",
    0xC057: "TLS_DHE_DSS_WITH_ARIA_256_GCM_SHA384",
    0xC058: "TLS_DH_DSS_WITH_ARIA_128_GCM_SHA256",
    0xC059: "TLS_DH_DSS_WITH_ARIA_256_GCM_SHA384",
    0xC05A: "TLS_DH_anon_WITH_ARIA_128_GCM_SHA256",
    0xC05B: "TLS_DH_anon_WITH_ARIA_256_GCM_SHA384",
    0xC05C: "TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256",
    0xC05D: "TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384",
    0xC05E: "TLS_ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256",
    0xC05F: "TLS_ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384",
    0xC060: "TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256",
    0xC061: "TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384",
    0xC062: "TLS_ECDH_RSA_WITH_ARIA_128_GCM_SHA256",
    0xC063: "TLS_ECDH_RSA_WITH_ARIA_256_GCM_SHA384",
    0xC064: "TLS_PSK_WITH_ARIA_128_CBC_SHA256",
    0xC065: "TLS_PSK_WITH_ARIA_256_CBC_SHA384",
    0xC066: "TLS_DHE_PSK_WITH_ARIA_128_CBC_SHA256",
    0xC067: "TLS_DHE_PSK_WITH_ARIA_256_CBC_SHA384",
    0xC068: "TLS_RSA_PSK_WITH_ARIA_128_CBC_SHA256",
    0xC069: "TLS_RSA_PSK_WITH_ARIA_256_CBC_SHA384",
    0xC06A: "TLS_PSK_WITH_ARIA_128_GCM_SHA256",
    0xC06B: "TLS_PSK_WITH_ARIA_256_GCM_SHA384",
    0xC06C: "TLS_DHE_PSK_WITH_ARIA_128_GCM_SHA256",
    0xC06D: "TLS_DHE_PSK_WITH_ARIA_256_GCM_SHA384",
    0xC06E: "TLS_RSA_PSK_WITH_ARIA_128_GCM_SHA256",
    0xC06F: "TLS_RSA_PSK_WITH_ARIA_256_GCM_SHA384",
    0xC070: "TLS_ECDHE_PSK_WITH_ARIA_128_CBC_SHA256",
    0xC071: "TLS_ECDHE_PSK_WITH_ARIA_256_CBC_SHA384",
    0xC072: "TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256",
    0xC073: "TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384",
    0xC074: "TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256",
    0xC075: "TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384",
    0xC076: "TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256",
    0xC077: "TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384",
    0xC078: "TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256",
    0xC079: "TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384",
    0xC07A: "TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256",
    0xC07B: "TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384",
    0xC07C: "TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256",
    0xC07D: "TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384",
    0xC07E: "TLS_DH_RSA_WITH_CAMELLIA_128_GCM_SHA256",
    0xC07F: "TLS_DH_RSA_WITH_CAMELLIA_256_GCM_SHA384",
    0xC080: "TLS_DHE_DSS_WITH_CAMELLIA_128_GCM_SHA256",
    0xC081: "TLS_DHE_DSS_WITH_CAMELLIA_256_GCM_SHA384",
    0xC082: "TLS_DH_DSS_WITH_CAMELLIA_128_GCM_SHA256",
    0xC083: "TLS_DH_DSS_WITH_CAMELLIA_256_GCM_SHA384",
    0xC084: "TLS_DH_anon_WITH_CAMELLIA_128_GCM_SHA256",
    0xC085: "TLS_DH_anon_WITH_CAMELLIA_256_GCM_SHA384",
    0xC086: "TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256",
    0xC087: "TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384",
    0xC088: "TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256",
    0xC089: "TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384",
    0xC08A: "TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256",
    0xC08B: "TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384",
    0xC08C: "TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256",
    0xC08D: "TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384",
    0xC08E: "TLS_PSK_WITH_CAMELLIA_128_GCM_SHA256",
    0xC08F: "TLS_PSK_WITH_CAMELLIA_256_GCM_SHA384",
    0xC090: "TLS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256",
    0xC091: "TLS_DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384",
    0xC092: "TLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256",
    0xC093: "TLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384",
    0xC094: "TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256",
    0xC095: "TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384",
    0xC096: "TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256",
    0xC097: "TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384",
    0xC098: "TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256",
    0xC099: "TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384",
    0xC09A: "TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256",
    0xC09B: "TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384",
    0xC09C: "TLS_RSA_WITH_AES_128_CCM",
    0xC09D: "TLS_RSA_WITH_AES_256_CCM",
    0xC09E: "TLS_DHE_RSA_WITH_AES_128_CCM",
    0xC09F: "TLS_DHE_RSA_WITH_AES_256_CCM",
    0xC0A0: "TLS_RSA_WITH_AES_128_CCM_8",
    0xC0A1: "TLS_RSA_WITH_AES_256_CCM_8",
    0xC0A2: "TLS_DHE_RSA_WITH_AES_128_CCM_8",
    0xC0A3: "TLS_DHE_RSA_WITH_AES_256_CCM_8",
    0xC0A4: "TLS_PSK_WITH_AES_128_CCM",
    0xC0A5: "TLS_PSK_WITH_AES_256_CCM",
    0xC0A6: "TLS_DHE_PSK_WITH_AES_128_CCM",
    0xC0A7: "TLS_DHE_PSK_WITH_AES_256_CCM",
    0xC0A8: "TLS_PSK_WITH_AES_128_CCM_8",
    0xC0A9: "TLS_PSK_WITH_AES_256_CCM_8",
    0xC0AA: "TLS_PSK_DHE_WITH_AES_128_CCM_8",
    0xC0AB: "TLS_PSK_DHE_WITH_AES_256_CCM_8",
    0xC0AC: "TLS_ECDHE_ECDSA_WITH_AES_128_CCM",
    0xC0AD: "TLS_ECDHE_ECDSA_WITH_AES_256_CCM",
    0xC0AE: "TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8",
    0xC0AF: "TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8",
    # Experimental
    0xCC13: "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305",
    0xCC14: "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305",
    0xCC15: "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
    # Special
    0x5600: "TLS_FALLBACK_SCSV",
    0xFF00: "TLS_EMPTY_RENEGOTIATION_INFO_SCSV",
}

# Ciphers suites sent by Chrome
chrome_ciphers = [
    TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
    TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
    TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
    TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
    TLS_ECDHE_ECDSA_WITH_RC4_128_SHA,
    TLS_ECDHE_RSA_WITH_RC4_128_SHA,
    TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
    TLS_DHE_DSS_WITH_AES_128_CBC_SHA,
    TLS_DHE_RSA_WITH_AES_256_CBC_SHA,
    TLS_RSA_WITH_AES_128_CBC_SHA,
    TLS_RSA_WITH_AES_256_CBC_SHA,
    TLS_RSA_WITH_3DES_EDE_CBC_SHA,
    TLS_RSA_WITH_RC4_128_SHA,
    TLS_RSA_WITH_RC4_128_MD5,
]

# generate reverse map:
# d = {}
# for key in locals().keys():
#     if key.startswith('TLS'):
#         d[locals()[key]] = key

# for key in sorted(d.keys()):
#     print ('%s: \'%s\',' % (hex(key), d[key]))
