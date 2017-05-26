from enum import IntEnum


class KeyType(IntEnum):
    """
    Key types known by PKCS#11.

    Making use of a given key type requires the appropriate
    :class:`Mechanism` to be available.
    """
    RSA            = 0x00000000
    """
    See the `RSA section
    <http://docs.oasis-open.org/pkcs11/pkcs11-curr/v2.40/errata01/os/pkcs11-curr-v2.40-errata01-os-complete.html#_Toc441850404>`_
    of PKCS#11 specification for valid :class:`Mechanism` and
    :class:`pkcs11.constants.Attribute` types.
    """
    DSA            = 0x00000001
    DH             = 0x00000002
    """
    See the `Diffie-Hellman section
    <http://docs.oasis-open.org/pkcs11/pkcs11-curr/v2.40/errata01/os/pkcs11-curr-v2.40-errata01-os-complete.html#_Toc441850461>`_
    of the PKCS#11 specification for valid :class:`Mechanism` and
    :class:`pkcs11.constants.Attribute` types.
    """
    ECDSA          = 0x00000003
    EC             = 0x00000003
    X9_42_DH       = 0x00000004
    KEA            = 0x00000005
    GENERIC_SECRET = 0x00000010
    RC2            = 0x00000011
    RC4            = 0x00000012
    DES            = 0x00000013
    DES2           = 0x00000014
    DES3           = 0x00000015
    CAST           = 0x00000016
    CAST3          = 0x00000017
    CAST5          = 0x00000018
    CAST128        = 0x00000018
    RC5            = 0x00000019
    IDEA           = 0x0000001A
    SKIPJACK       = 0x0000001B
    BATON          = 0x0000001C
    JUNIPER        = 0x0000001D
    CDMF           = 0x0000001E
    AES            = 0x0000001F
    """
    See the `AES section
    <http://docs.oasis-open.org/pkcs11/pkcs11-curr/v2.40/errata01/os/pkcs11-curr-v2.40-errata01-os-complete.html#_Toc441850484>`_
    of PKCS#11 for valid :class:`Mechanism` and
    :class:`pkcs11.constants.Attribute` types.
    """
    BLOWFISH       = 0x00000020
    TWOFISH        = 0x00000021
    SECURID        = 0x00000022
    HOTP           = 0x00000023
    ACTI           = 0x00000024
    CAMELLIA       = 0x00000025
    ARIA           = 0x00000026
    MD5_HMAC       = 0x00000027
    SHA_1_HMAC     = 0x00000028
    RIPEMD128_HMAC = 0x00000029
    RIPEMD160_HMAC = 0x0000002A
    SHA256_HMAC    = 0x0000002B
    SHA384_HMAC    = 0x0000002C
    SHA512_HMAC    = 0x0000002D
    SHA224_HMAC    = 0x0000002E
    SEED           = 0x0000002F
    GOSTR3410      = 0x00000030
    GOSTR3411      = 0x00000031
    GOST28147      = 0x00000032

    VENDOR_DEFINED = 0x80000000

    def __repr__(self):
        return '<KeyType.%s>' % self.name


class Mechanism(IntEnum):
    """
    Cryptographic mechanisms known by PKCS#11.

    The list of supported cryptographic mechanisms for a :class:`pkcs11.Slot`
    can be retrieved with :meth:`pkcs11.Slot.get_mechanisms()`.

    Descriptions of the `current
    <http://docs.oasis-open.org/pkcs11/pkcs11-curr/v2.40/pkcs11-curr-v2.40.html>`_
    and `historical
    <http://docs.oasis-open.org/pkcs11/pkcs11-hist/v2.40/pkcs11-hist-v2.40.html>`_
    mechanisms, including their valid :class:`pkcs11.constants.Attribute`
    types and `mechanism_param` can be found in the PKCS#11 specification.
    """

    RSA_PKCS_KEY_PAIR_GEN    = 0x00000000
    """Default for generating :attr:`KeyType.RSA` keys."""
    RSA_PKCS                 = 0x00000001
    """Default for encrypting/decrypting with :attr:`KeyType.RSA` keys."""
    RSA_9796                 = 0x00000002
    RSA_X_509                = 0x00000003

    MD2_RSA_PKCS             = 0x00000004
    MD5_RSA_PKCS             = 0x00000005
    SHA1_RSA_PKCS            = 0x00000006

    RIPEMD128_RSA_PKCS       = 0x00000007
    RIPEMD160_RSA_PKCS       = 0x00000008
    RSA_PKCS_OAEP            = 0x00000009

    RSA_X9_31_KEY_PAIR_GEN   = 0x0000000A
    RSA_X9_31                = 0x0000000B
    SHA1_RSA_X9_31           = 0x0000000C
    RSA_PKCS_PSS             = 0x0000000D
    SHA1_RSA_PKCS_PSS        = 0x0000000E

    DSA_KEY_PAIR_GEN         = 0x00000010
    DSA                      = 0x00000011
    DSA_SHA1                 = 0x00000012
    DSA_SHA224               = 0x00000013
    DSA_SHA256               = 0x00000014
    DSA_SHA384               = 0x00000015
    DSA_SHA512               = 0x00000016
    DH_PKCS_KEY_PAIR_GEN     = 0x00000020
    DH_PKCS_DERIVE           = 0x00000021

    X9_42_DH_KEY_PAIR_GEN    = 0x00000030
    X9_42_DH_DERIVE          = 0x00000031
    X9_42_DH_HYBRID_DERIVE   = 0x00000032
    X9_42_MQV_DERIVE         = 0x00000033

    SHA256_RSA_PKCS          = 0x00000040
    SHA384_RSA_PKCS          = 0x00000041
    SHA512_RSA_PKCS          = 0x00000042
    """Default for signing/verification with :attr:`KeyType.RSA` keys."""
    SHA256_RSA_PKCS_PSS      = 0x00000043
    SHA384_RSA_PKCS_PSS      = 0x00000044
    SHA512_RSA_PKCS_PSS      = 0x00000045

    SHA224_RSA_PKCS          = 0x00000046
    SHA224_RSA_PKCS_PSS      = 0x00000047

    RC2_KEY_GEN              = 0x00000100
    RC2_ECB                  = 0x00000101
    RC2_CBC                  = 0x00000102
    RC2_MAC                  = 0x00000103

    RC2_MAC_GENERAL          = 0x00000104
    RC2_CBC_PAD              = 0x00000105

    RC4_KEY_GEN              = 0x00000110
    RC4                      = 0x00000111
    DES_KEY_GEN              = 0x00000120
    DES_ECB                  = 0x00000121
    DES_CBC                  = 0x00000122
    DES_MAC                  = 0x00000123

    DES_MAC_GENERAL          = 0x00000124
    DES_CBC_PAD              = 0x00000125

    DES2_KEY_GEN             = 0x00000130
    DES3_KEY_GEN             = 0x00000131
    DES3_ECB                 = 0x00000132
    DES3_CBC                 = 0x00000133
    DES3_MAC                 = 0x00000134

    DES3_MAC_GENERAL         = 0x00000135
    DES3_CBC_PAD             = 0x00000136
    DES3_CMAC_GENERAL        = 0x00000137
    DES3_CMAC                = 0x00000138
    CDMF_KEY_GEN             = 0x00000140
    CDMF_ECB                 = 0x00000141
    CDMF_CBC                 = 0x00000142
    CDMF_MAC                 = 0x00000143
    CDMF_MAC_GENERAL         = 0x00000144
    CDMF_CBC_PAD             = 0x00000145

    DES_OFB64                = 0x00000150
    DES_OFB8                 = 0x00000151
    DES_CFB64                = 0x00000152
    DES_CFB8                 = 0x00000153

    MD2                      = 0x00000200

    MD2_HMAC                 = 0x00000201
    MD2_HMAC_GENERAL         = 0x00000202

    MD5                      = 0x00000210

    MD5_HMAC                 = 0x00000211
    MD5_HMAC_GENERAL         = 0x00000212

    SHA_1                    = 0x00000220

    SHA_1_HMAC               = 0x00000221
    SHA_1_HMAC_GENERAL       = 0x00000222

    RIPEMD128                = 0x00000230
    RIPEMD128_HMAC           = 0x00000231
    RIPEMD128_HMAC_GENERAL   = 0x00000232
    RIPEMD160                = 0x00000240
    RIPEMD160_HMAC           = 0x00000241
    RIPEMD160_HMAC_GENERAL   = 0x00000242

    SHA256                   = 0x00000250
    SHA256_HMAC              = 0x00000251
    SHA256_HMAC_GENERAL      = 0x00000252

    SHA224                   = 0x00000255
    SHA224_HMAC              = 0x00000256
    SHA224_HMAC_GENERAL      = 0x00000257
    SHA384                   = 0x00000260
    SHA384_HMAC              = 0x00000261
    SHA384_HMAC_GENERAL      = 0x00000262
    SHA512                   = 0x00000270
    SHA512_HMAC              = 0x00000271
    """This is the default for signing/verification with :class:`KeyType.AES`."""
    SHA512_HMAC_GENERAL      = 0x00000272
    SECURID_KEY_GEN          = 0x00000280
    SECURID                  = 0x00000282
    HOTP_KEY_GEN             = 0x00000290
    HOTP                     = 0x00000291
    ACTI                     = 0x000002A0
    ACTI_KEY_GEN             = 0x000002A1

    CAST_KEY_GEN             = 0x00000300
    CAST_ECB                 = 0x00000301
    CAST_CBC                 = 0x00000302
    CAST_MAC                 = 0x00000303
    CAST_MAC_GENERAL         = 0x00000304
    CAST_CBC_PAD             = 0x00000305
    CAST3_KEY_GEN            = 0x00000310
    CAST3_ECB                = 0x00000311
    CAST3_CBC                = 0x00000312
    CAST3_MAC                = 0x00000313
    CAST3_MAC_GENERAL        = 0x00000314
    CAST3_CBC_PAD            = 0x00000315

    CAST5_KEY_GEN            = 0x00000320
    CAST128_KEY_GEN          = 0x00000320
    CAST5_ECB                = 0x00000321
    CAST128_ECB              = 0x00000321
    CAST5_CBC                = 0x00000322
    CAST128_CBC              = 0x00000322
    CAST5_MAC                = 0x00000323
    CAST128_MAC              = 0x00000323
    CAST5_MAC_GENERAL        = 0x00000324
    CAST128_MAC_GENERAL      = 0x00000324
    CAST5_CBC_PAD            = 0x00000325
    CAST128_CBC_PAD          = 0x00000325
    RC5_KEY_GEN              = 0x00000330
    RC5_ECB                  = 0x00000331
    RC5_CBC                  = 0x00000332
    RC5_MAC                  = 0x00000333
    RC5_MAC_GENERAL          = 0x00000334
    RC5_CBC_PAD              = 0x00000335
    IDEA_KEY_GEN             = 0x00000340
    IDEA_ECB                 = 0x00000341
    IDEA_CBC                 = 0x00000342
    IDEA_MAC                 = 0x00000343
    IDEA_MAC_GENERAL         = 0x00000344
    IDEA_CBC_PAD             = 0x00000345
    GENERIC_SECRET_KEY_GEN   = 0x00000350
    CONCATENATE_BASE_AND_KEY = 0x00000360
    CONCATENATE_BASE_AND_DATA= 0x00000362
    CONCATENATE_DATA_AND_BASE= 0x00000363
    XOR_BASE_AND_DATA        = 0x00000364
    EXTRACT_KEY_FROM_KEY     = 0x00000365
    SSL3_PRE_MASTER_KEY_GEN  = 0x00000370
    SSL3_MASTER_KEY_DERIVE   = 0x00000371
    SSL3_KEY_AND_MAC_DERIVE  = 0x00000372

    SSL3_MASTER_KEY_DERIVE_DH= 0x00000373
    TLS_PRE_MASTER_KEY_GEN   = 0x00000374
    TLS_MASTER_KEY_DERIVE    = 0x00000375
    TLS_KEY_AND_MAC_DERIVE   = 0x00000376
    TLS_MASTER_KEY_DERIVE_DH = 0x00000377

    TLS_PRF                  = 0x00000378

    SSL3_MD5_MAC             = 0x00000380
    SSL3_SHA1_MAC            = 0x00000381
    MD5_KEY_DERIVATION       = 0x00000390
    MD2_KEY_DERIVATION       = 0x00000391
    SHA1_KEY_DERIVATION      = 0x00000392

    SHA256_KEY_DERIVATION    = 0x00000393
    SHA384_KEY_DERIVATION    = 0x00000394
    SHA512_KEY_DERIVATION    = 0x00000395

    SHA224_KEY_DERIVATION    = 0x00000396

    PBE_MD2_DES_CBC          = 0x000003A0
    PBE_MD5_DES_CBC          = 0x000003A1
    PBE_MD5_CAST_CBC         = 0x000003A2
    PBE_MD5_CAST3_CBC        = 0x000003A3
    PBE_MD5_CAST5_CBC        = 0x000003A4
    PBE_MD5_CAST128_CBC      = 0x000003A4
    PBE_SHA1_CAST5_CBC       = 0x000003A5
    PBE_SHA1_CAST128_CBC     = 0x000003A5
    PBE_SHA1_RC4_128         = 0x000003A6
    PBE_SHA1_RC4_40          = 0x000003A7
    PBE_SHA1_DES3_EDE_CBC    = 0x000003A8
    PBE_SHA1_DES2_EDE_CBC    = 0x000003A9
    PBE_SHA1_RC2_128_CBC     = 0x000003AA
    PBE_SHA1_RC2_40_CBC      = 0x000003AB

    PKCS5_PBKD2              = 0x000003B0

    PBA_SHA1_WITH_SHA1_HMAC  = 0x000003C0

    WTLS_PRE_MASTER_KEY_GEN  = 0x000003D0
    WTLS_MASTER_KEY_DERIVE   = 0x000003D1
    WTLS_MASTER_KEY_DERIVE_DH_ECC = 0x000003D2
    WTLS_PRF                 = 0x000003D3
    WTLS_SERVER_KEY_AND_MAC_DERIVE = 0x000003D4
    WTLS_CLIENT_KEY_AND_MAC_DERIVE = 0x000003D5

    KEY_WRAP_LYNKS           = 0x00000400
    KEY_WRAP_SET_OAEP        = 0x00000401

    CMS_SIG                  = 0x00000500

    KIP_DERIVE               = 0x00000510
    KIP_WRAP                 = 0x00000511
    KIP_MAC                  = 0x00000512

    CAMELLIA_KEY_GEN         = 0x00000550
    CAMELLIA_ECB             = 0x00000551
    CAMELLIA_CBC             = 0x00000552
    CAMELLIA_MAC             = 0x00000553
    CAMELLIA_MAC_GENERAL     = 0x00000554
    CAMELLIA_CBC_PAD         = 0x00000555
    CAMELLIA_ECB_ENCRYPT_DATA= 0x00000556
    CAMELLIA_CBC_ENCRYPT_DATA= 0x00000557
    CAMELLIA_CTR             = 0x00000558

    ARIA_KEY_GEN             = 0x00000560
    ARIA_ECB                 = 0x00000561
    ARIA_CBC                 = 0x00000562
    ARIA_MAC                 = 0x00000563
    ARIA_MAC_GENERAL         = 0x00000564
    ARIA_CBC_PAD             = 0x00000565
    ARIA_ECB_ENCRYPT_DATA    = 0x00000566
    ARIA_CBC_ENCRYPT_DATA    = 0x00000567

    SEED_KEY_GEN             = 0x00000650
    SEED_ECB                 = 0x00000651
    SEED_CBC                 = 0x00000652
    SEED_MAC                 = 0x00000653
    SEED_MAC_GENERAL         = 0x00000654
    SEED_CBC_PAD             = 0x00000655
    SEED_ECB_ENCRYPT_DATA    = 0x00000656
    SEED_CBC_ENCRYPT_DATA    = 0x00000657

    SKIPJACK_KEY_GEN         = 0x00001000
    SKIPJACK_ECB64           = 0x00001001
    SKIPJACK_CBC64           = 0x00001002
    SKIPJACK_OFB64           = 0x00001003
    SKIPJACK_CFB64           = 0x00001004
    SKIPJACK_CFB32           = 0x00001005
    SKIPJACK_CFB16           = 0x00001006
    SKIPJACK_CFB8            = 0x00001007
    SKIPJACK_WRAP            = 0x00001008
    SKIPJACK_PRIVATE_WRAP    = 0x00001009
    SKIPJACK_RELAYX          = 0x0000100a
    KEA_KEY_PAIR_GEN         = 0x00001010
    KEA_KEY_DERIVE           = 0x00001011
    FORTEZZA_TIMESTAMP       = 0x00001020
    BATON_KEY_GEN            = 0x00001030
    BATON_ECB128             = 0x00001031
    BATON_ECB96              = 0x00001032
    BATON_CBC128             = 0x00001033
    BATON_COUNTER            = 0x00001034
    BATON_SHUFFLE            = 0x00001035
    BATON_WRAP               = 0x00001036

    ECDSA_KEY_PAIR_GEN       = 0x00001040
    EC_KEY_PAIR_GEN          = 0x00001040

    ECDSA                    = 0x00001041
    ECDSA_SHA1               = 0x00001042
    ECDSA_SHA224             = 0x00001043
    ECDSA_SHA256             = 0x00001044
    ECDSA_SHA384             = 0x00001045
    ECDSA_SHA512             = 0x00001046

    ECDH1_DERIVE             = 0x00001050
    ECDH1_COFACTOR_DERIVE    = 0x00001051
    ECMQV_DERIVE             = 0x00001052

    JUNIPER_KEY_GEN          = 0x00001060
    JUNIPER_ECB128           = 0x00001061
    JUNIPER_CBC128           = 0x00001062
    JUNIPER_COUNTER          = 0x00001063
    JUNIPER_SHUFFLE          = 0x00001064
    JUNIPER_WRAP             = 0x00001065
    FASTHASH                 = 0x00001070

    AES_KEY_GEN              = 0x00001080
    """Default for generating :attr:`KeyType.AES` keys."""
    AES_ECB                  = 0x00001081
    AES_CBC                  = 0x00001082
    AES_MAC                  = 0x00001083
    AES_MAC_GENERAL          = 0x00001084
    AES_CBC_PAD              = 0x00001085
    """
    Default for encrypting/decrypting with :attr:`KeyType.AES` keys. Includes
    PKCS#7 padding to pad files to a whole number of blocks.

    Requires a 128-bit initialisation vector passed as `mechanism_param`.
    """
    AES_CTR                  = 0x00001086
    AES_CTS                  = 0x00001089
    AES_CMAC                 = 0x0000108A
    AES_CMAC_GENERAL         = 0x0000108B

    BLOWFISH_KEY_GEN         = 0x00001090
    BLOWFISH_CBC             = 0x00001091
    TWOFISH_KEY_GEN          = 0x00001092
    TWOFISH_CBC              = 0x00001093

    AES_GCM                  = 0x00001087
    AES_CCM                  = 0x00001088
    AES_KEY_WRAP             = 0x00001090
    AES_KEY_WRAP_PAD         = 0x00001091

    BLOWFISH_CBC_PAD         = 0x00001094
    TWOFISH_CBC_PAD          = 0x00001095

    DES_ECB_ENCRYPT_DATA     = 0x00001100
    DES_CBC_ENCRYPT_DATA     = 0x00001101
    DES3_ECB_ENCRYPT_DATA    = 0x00001102
    DES3_CBC_ENCRYPT_DATA    = 0x00001103
    AES_ECB_ENCRYPT_DATA     = 0x00001104
    AES_CBC_ENCRYPT_DATA     = 0x00001105

    GOSTR3410_KEY_PAIR_GEN   = 0x00001200
    GOSTR3410                = 0x00001201
    GOSTR3410_WITH_GOSTR3411 = 0x00001202
    GOSTR3410_KEY_WRAP       = 0x00001203
    GOSTR3410_DERIVE         = 0x00001204
    GOSTR3411                = 0x00001210
    GOSTR3411_HMAC           = 0x00001211
    GOST28147_KEY_GEN        = 0x00001220
    GOST28147_ECB            = 0x00001221
    GOST28147                = 0x00001222
    GOST28147_MAC            = 0x00001223
    GOST28147_KEY_WRAP       = 0x00001224

    DSA_PARAMETER_GEN        = 0x00002000
    DH_PKCS_PARAMETER_GEN    = 0x00002001
    X9_42_DH_PARAMETER_GEN   = 0x00002002

    AES_OFB                  = 0x00002104
    AES_CFB64                = 0x00002105
    AES_CFB8                 = 0x00002106
    AES_CFB128               = 0x00002107

    RSA_PKCS_TPM_1_1         = 0x00004001
    RSA_PKCS_OAEP_TPM_1_1    = 0x00004002

    VENDOR_DEFINED           = 0x80000000

    def __repr__(self):
        return '<Mechanism.%s>' % self.name
