package com.cryptocheck;

import javacard.framework.*;
import javacard.security.*;
import javacardx.crypto.*;

/**
 * Simple applet that enumerates supported cryptographic algorithms on a
 * Java Card.  The applet was originally scanning the whole range of possible
 * algorithm identifiers which resulted in attempts to use undefined values.
 * The implementation now iterates over explicit lists of official constants
 * for each algorithm family.
 */
public class CryptoCheckApplet extends Applet {

    // CLA for all commands
    private static final byte CLA_STANDARD = (byte) 0x00;

    // Instruction codes used to trigger individual enumerations
    private static final byte INS_ENUM_CIPHERS       = (byte) 0x10;
    private static final byte INS_ENUM_SIGNATURES    = (byte) 0x12;
    private static final byte INS_ENUM_DIGESTS       = (byte) 0x14;
    private static final byte INS_ENUM_RANDOMS       = (byte) 0x16;
    private static final byte INS_ENUM_KEY_AGREEMENT = (byte) 0x18;
    private static final byte INS_ENUM_EC_CURVES     = (byte) 0x1A;
    private static final byte INS_GET_RESPONSE       = (byte) 0xC0;

    private static final short MAX_RESPONSE_LENGTH = (short) 512;
    private final byte[] responseBuffer = new byte[MAX_RESPONSE_LENGTH];
    private short responseLength = 0;
    private short responseOffset = 0;

    /**
     * Array of cipher algorithm identifiers to probe.
     */
    private static final short[] CIPHER_ALGS = {
        Cipher.ALG_DES_ECB_NOPAD,
        Cipher.ALG_DES_CBC_NOPAD,
        Cipher.ALG_DES_CBC_ISO9797_M1,
        Cipher.ALG_DES_CBC_ISO9797_M2,
        Cipher.ALG_DES_CBC_PKCS5,
        Cipher.ALG_DES_ECB_ISO9797_M1,
        Cipher.ALG_DES_ECB_ISO9797_M2,
        Cipher.ALG_DES3_ECB_NOPAD,
        Cipher.ALG_DES3_CBC_NOPAD,
        Cipher.ALG_DES3_CBC_ISO9797_M1,
        Cipher.ALG_DES3_CBC_ISO9797_M2,
        Cipher.ALG_AES_BLOCK_128_ECB_NOPAD,
        Cipher.ALG_AES_BLOCK_128_CBC_NOPAD,
        Cipher.ALG_AES_BLOCK_128_CBC_PKCS5,
        Cipher.ALG_AES_ECB_ISO9797_M1,
        Cipher.ALG_AES_ECB_ISO9797_M2,
        Cipher.ALG_AES_CBC_ISO9797_M1,
        Cipher.ALG_AES_CBC_ISO9797_M2,
        Cipher.ALG_AES_CTR,
        Cipher.ALG_AES_GCM,
        Cipher.ALG_AES_CCM,
        Cipher.ALG_AES_KW,
        Cipher.ALG_AES_KWP,
        Cipher.ALG_KOREA_ARIA_ECB_NOPAD,
        Cipher.ALG_KOREA_ARIA_CBC_NOPAD,
        Cipher.ALG_KOREA_SEED_ECB_NOPAD,
        Cipher.ALG_KOREA_SEED_CBC_NOPAD,
        Cipher.ALG_SM4_ECB_NOPAD,
        Cipher.ALG_SM4_CBC_NOPAD,
        Cipher.ALG_ARCFOUR,
        Cipher.ALG_RSA_NOPAD,
        Cipher.ALG_RSA_PKCS1,
        Cipher.ALG_RSA_ISO14888,
        Cipher.ALG_RSA_ISO9796,
        Cipher.ALG_RSA_ISO9796_MR
    };

    /**
     * Array of signature algorithm identifiers to probe.
     */
    private static final short[] SIGNATURE_ALGS = {
        Signature.ALG_DES_MAC4_NOPAD,
        Signature.ALG_DES_MAC8_NOPAD,
        Signature.ALG_DES_MAC4_ISO9797_M1,
        Signature.ALG_DES_MAC8_ISO9797_M1,
        Signature.ALG_DES_MAC4_ISO9797_M2,
        Signature.ALG_DES_MAC8_ISO9797_M2,
        Signature.ALG_DES_MAC4_PKCS5,
        Signature.ALG_DES_MAC8_PKCS5,
        Signature.ALG_AES_MAC_128_NOPAD,
        Signature.ALG_AES_MAC_192_NOPAD,
        Signature.ALG_AES_MAC_256_NOPAD,
        Signature.ALG_AES_CMAC_128,
        Signature.ALG_AES_CMAC_192,
        Signature.ALG_AES_CMAC_256,
        Signature.ALG_AES_GMAC,
        Signature.ALG_RSA_MD5_PKCS1,
        Signature.ALG_RSA_SHA_PKCS1,
        Signature.ALG_RSA_SHA_224_PKCS1,
        Signature.ALG_RSA_SHA_256_PKCS1,
        Signature.ALG_RSA_SHA_384_PKCS1,
        Signature.ALG_RSA_SHA_512_PKCS1,
        Signature.ALG_RSA_SHA3_224_PKCS1,
        Signature.ALG_RSA_SHA3_256_PKCS1,
        Signature.ALG_RSA_SHA3_384_PKCS1,
        Signature.ALG_RSA_SHA3_512_PKCS1,
        Signature.ALG_RSA_SHA_PSS,
        Signature.ALG_RSA_SHA_224_PSS,
        Signature.ALG_RSA_SHA_256_PSS,
        Signature.ALG_RSA_SHA_384_PSS,
        Signature.ALG_RSA_SHA_512_PSS,
        Signature.ALG_RSA_SHA3_224_PSS,
        Signature.ALG_RSA_SHA3_256_PSS,
        Signature.ALG_RSA_SHA3_384_PSS,
        Signature.ALG_RSA_SHA3_512_PSS,
        Signature.ALG_RSA_SHA_ISO9796,
        Signature.ALG_RSA_SHA_ISO9796_MR,
        Signature.ALG_RSA_MD5_ISO9796,
        Signature.ALG_RSA_RIPEMD160_ISO9796,
        Signature.ALG_RSA_RIPEMD160_PKCS1,
        Signature.ALG_DSA_SHA,
        Signature.ALG_DSA_SHA_224,
        Signature.ALG_DSA_SHA_256,
        Signature.ALG_ECDSA_SHA,
        Signature.ALG_ECDSA_SHA_224,
        Signature.ALG_ECDSA_SHA_256,
        Signature.ALG_ECDSA_SHA_384,
        Signature.ALG_ECDSA_SHA_512,
        Signature.ALG_ECDSA_SHA3_224,
        Signature.ALG_ECDSA_SHA3_256,
        Signature.ALG_ECDSA_SHA3_384,
        Signature.ALG_ECDSA_SHA3_512,
        Signature.ALG_ECDSA_RIPEMD160,
        Signature.ALG_SM2_SM3,
        Signature.ALG_HMAC_MD5,
        Signature.ALG_HMAC_SHA1,
        Signature.ALG_HMAC_SHA_224,
        Signature.ALG_HMAC_SHA_256,
        Signature.ALG_HMAC_SHA_384,
        Signature.ALG_HMAC_SHA_512,
        Signature.ALG_HMAC_SHA3_224,
        Signature.ALG_HMAC_SHA3_256,
        Signature.ALG_HMAC_SHA3_384,
        Signature.ALG_HMAC_SHA3_512,
        Signature.ALG_HMAC_SM3
    };

    /**
     * Array of message digest algorithm identifiers to probe.
     */
    private static final short[] DIGEST_ALGS = {
        MessageDigest.ALG_MD5,
        MessageDigest.ALG_SHA,
        MessageDigest.ALG_SHA_224,
        MessageDigest.ALG_SHA_256,
        MessageDigest.ALG_SHA_384,
        MessageDigest.ALG_SHA_512,
        MessageDigest.ALG_SHA3_224,
        MessageDigest.ALG_SHA3_256,
        MessageDigest.ALG_SHA3_384,
        MessageDigest.ALG_SHA3_512,
        MessageDigest.ALG_RIPEMD160,
        MessageDigest.ALG_SM3
    };

    /**
     * Array of random data algorithm identifiers to probe.
     */
    private static final short[] RANDOM_ALGS = {
        RandomData.ALG_PSEUDO_RANDOM,
        RandomData.ALG_SECURE_RANDOM,
        RandomData.ALG_TRNG
    };

    /**
     * Array of key agreement algorithm identifiers to probe.
     */
    private static final short[] KEY_AGREEMENT_ALGS = {
        KeyAgreement.ALG_EC_SVDP_DH_PLAIN,
        KeyAgreement.ALG_EC_SVDP_DH_PLAIN_XY,
        KeyAgreement.ALG_EC_SVDP_DH_KDF,
        KeyAgreement.ALG_EC_SVDP_DHC,
        KeyAgreement.ALG_EC_SVDP_DHC_KDF,
        KeyAgreement.ALG_EC_SVDP_DH_PLAIN_X25519,
        KeyAgreement.ALG_EC_SVDP_DH_PLAIN_X448,
        KeyAgreement.ALG_DH_PLAIN,
        KeyAgreement.ALG_DH_KDF,
        KeyAgreement.ALG_DH_PLAIN_XY
    };

    /**
     * Array of named elliptic-curve identifiers to probe.
     */
    private static final short[] EC_CURVES = {
        NamedParameterSpec.SECP160K1,
        NamedParameterSpec.SECP160R1,
        NamedParameterSpec.SECP160R2,
        NamedParameterSpec.SECP192K1,
        NamedParameterSpec.SECP192R1,
        NamedParameterSpec.SECP224K1,
        NamedParameterSpec.SECP224R1,
        NamedParameterSpec.SECP256K1,
        NamedParameterSpec.SECP256R1,
        NamedParameterSpec.SECP384R1,
        NamedParameterSpec.SECP521R1,
        NamedParameterSpec.BRAINPOOLP160R1,
        NamedParameterSpec.BRAINPOOLP192R1,
        NamedParameterSpec.BRAINPOOLP224R1,
        NamedParameterSpec.BRAINPOOLP256R1,
        NamedParameterSpec.BRAINPOOLP320R1,
        NamedParameterSpec.BRAINPOOLP384R1,
        NamedParameterSpec.BRAINPOOLP512R1,
        NamedParameterSpec.X25519,
        NamedParameterSpec.X448,
        NamedParameterSpec.ED25519,
        NamedParameterSpec.ED448
    };

    private CryptoCheckApplet() {
        register();
    }

    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new CryptoCheckApplet();
    }

    /**
     * APDU interface. Each command uses CLA=0x00 and no command data. INS
     * selects the operation:
     * <ul>
     *   <li>{@link #INS_ENUM_CIPHERS}</li>
     *   <li>{@link #INS_ENUM_SIGNATURES}</li>
     *   <li>{@link #INS_ENUM_DIGESTS}</li>
     *   <li>{@link #INS_ENUM_RANDOMS}</li>
     *   <li>{@link #INS_ENUM_KEY_AGREEMENT}</li>
     *   <li>{@link #INS_ENUM_EC_CURVES}</li>
     * </ul>
     * The response is a sequence of 16-bit algorithm identifiers. Errors are
     * reported using ISO7816/GP status words.
     */
    public void process(APDU apdu) {
        byte[] buf = apdu.getBuffer();

        if (selectingApplet()) {
            return;
        }

        if (buf[ISO7816.OFFSET_CLA] != CLA_STANDARD) {
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }

        byte ins = buf[ISO7816.OFFSET_INS];

        if (ins == INS_GET_RESPONSE) {
            if (responseLength == 0) {
                ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);
            }
            sendChained(apdu);
            return;
        }

        if (buf[ISO7816.OFFSET_P1] != (byte) 0x00 || buf[ISO7816.OFFSET_P2] != (byte) 0x00) {
            ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
        }

        if (apdu.getIncomingLength() != 0) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        short len;

        switch (ins) {
            case INS_ENUM_CIPHERS:
                len = enumerateCiphers(responseBuffer, (short) 0);
                break;
            case INS_ENUM_SIGNATURES:
                len = enumerateSignatures(responseBuffer, (short) 0);
                break;
            case INS_ENUM_DIGESTS:
                len = enumerateDigests(responseBuffer, (short) 0);
                break;
            case INS_ENUM_RANDOMS:
                len = enumerateRandoms(responseBuffer, (short) 0);
                break;
            case INS_ENUM_KEY_AGREEMENT:
                len = enumerateKeyAgreements(responseBuffer, (short) 0);
                break;
            case INS_ENUM_EC_CURVES:
                len = enumerateNamedCurves(responseBuffer, (short) 0);
                break;
            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
                return; // not reached
        }

        if (len > MAX_RESPONSE_LENGTH) {
            ISOException.throwIt(ISO7816.SW_FILE_FULL);
        }

        responseLength = len;
        responseOffset = 0;
        sendChained(apdu);
    }

    /**
     * Enumerate available cipher algorithms.
     */
    private short enumerateCiphers(byte[] out, short offset) {
        for (short i = 0; i < (short) CIPHER_ALGS.length; i++) {
            short alg = CIPHER_ALGS[i];
            try {
                Cipher.getInstance(alg, false);
                Util.setShort(out, offset, alg);
                offset += 2;
            } catch (CryptoException e) {
                // unsupported, ignore
            }
        }
        return offset;
    }

    /**
     * Enumerate available signature algorithms.
     */
    private short enumerateSignatures(byte[] out, short offset) {
        for (short i = 0; i < (short) SIGNATURE_ALGS.length; i++) {
            short alg = SIGNATURE_ALGS[i];
            try {
                Signature.getInstance(alg, false);
                Util.setShort(out, offset, alg);
                offset += 2;
            } catch (CryptoException e) {
                // unsupported, ignore
            }
        }
        return offset;
    }

    /**
     * Enumerate available message digest algorithms.
     */
    private short enumerateDigests(byte[] out, short offset) {
        for (short i = 0; i < (short) DIGEST_ALGS.length; i++) {
            short alg = DIGEST_ALGS[i];
            try {
                MessageDigest.getInstance(alg, false);
                Util.setShort(out, offset, alg);
                offset += 2;
            } catch (CryptoException e) {
                // unsupported, ignore
            }
        }
        return offset;
    }

    /**
     * Enumerate available random data generators.
     */
    private short enumerateRandoms(byte[] out, short offset) {
        for (short i = 0; i < (short) RANDOM_ALGS.length; i++) {
            short alg = RANDOM_ALGS[i];
            try {
                RandomData.getInstance(alg);
                Util.setShort(out, offset, alg);
                offset += 2;
            } catch (CryptoException e) {
                // unsupported, ignore
            }
        }
        return offset;
    }

    /**
     * Enumerate available key agreement algorithms.
     */
    private short enumerateKeyAgreements(byte[] out, short offset) {
        for (short i = 0; i < (short) KEY_AGREEMENT_ALGS.length; i++) {
            short alg = KEY_AGREEMENT_ALGS[i];
            try {
                KeyAgreement.getInstance(alg, false);
                Util.setShort(out, offset, alg);
                offset += 2;
            } catch (CryptoException e) {
                // unsupported, ignore
            }
        }
        return offset;
    }

    /**
     * Enumerate supported named elliptic curve parameters.
     */
    private short enumerateNamedCurves(byte[] out, short offset) {
        for (short i = 0; i < (short) EC_CURVES.length; i++) {
            short curve = EC_CURVES[i];
            try {
                KeyPair kp = new KeyPair(KeyPair.ALG_EC_FP, curve);
                kp.genKeyPair();
                Util.setShort(out, offset, curve);
                offset += 2;
            } catch (CryptoException e) {
                // unsupported, ignore
            }
        }
        return offset;
    }

    /**
     * Send up to Le bytes from the response buffer and set SW=0x61XX if more
     * data remains.
     */
    private void sendChained(APDU apdu) {
        short le = apdu.setOutgoing();
        if (le == 0) {
            le = (short) 0x0100; // treat Le=0 as 256
        }
        short remaining = (short) (responseLength - responseOffset);
        short chunk = le;
        if (chunk > remaining) {
            chunk = remaining;
        }
        apdu.setOutgoingLength(chunk);
        apdu.sendBytesLong(responseBuffer, responseOffset, chunk);
        responseOffset += chunk;
        remaining = (short) (responseLength - responseOffset);
        if (remaining > 0) {
            short sw = (short) (ISO7816.SW_BYTES_REMAINING_00 |
                    (short) (remaining > (short) 0x00FF ? (short) 0x00FF : remaining));
            ISOException.throwIt(sw);
        }
        responseLength = 0;
        responseOffset = 0;
    }
}

