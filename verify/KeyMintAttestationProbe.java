package com.sandbox.verify;

import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyInfo;
import android.security.keystore.KeyProperties;

import org.json.JSONObject;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.ProviderException;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.Locale;

/**
 * Pure-Java Android Keystore / KeyMint attestation self-check.
 * Never throws: captures ProviderException/KeyStoreException cleanly on unlocked devices.
 */
final class KeyMintAttestationProbe {
    private static final String KEYSTORE_PROVIDER = "AndroidKeyStore";
    private static final String ATTESTATION_OID = "1.3.6.1.4.1.11129.2.1.17";
    private static final int TAG_ROOT_OF_TRUST = 704;

    @SuppressWarnings("deprecation")
    private static boolean isInsideSecureHardwareCompat(KeyInfo keyInfo) {
        return keyInfo.isInsideSecureHardware();
    }

    private KeyMintAttestationProbe() {}

    static JSONObject probe(String aliasSuffix) {
        JSONObject out = new JSONObject();
        String alias = "sandbox_probe_attest_" + aliasSuffix;
        KeyStore ks = null;
        try {
            byte[] challenge = new byte[16];
            new SecureRandom().nextBytes(challenge);

            KeyPairGenerator kpg = KeyPairGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_EC, KEYSTORE_PROVIDER);
            KeyGenParameterSpec spec = new KeyGenParameterSpec.Builder(
                    alias, KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY)
                .setAlgorithmParameterSpec(new ECGenParameterSpec("secp256r1"))
                .setDigests(KeyProperties.DIGEST_SHA256)
                .setAttestationChallenge(challenge)
                .build();
            kpg.initialize(spec);
            KeyPair kp = kpg.generateKeyPair();

            try {
                KeyFactory kf = KeyFactory.getInstance(kp.getPrivate().getAlgorithm(), KEYSTORE_PROVIDER);
                KeyInfo keyInfo = kf.getKeySpec(kp.getPrivate(), KeyInfo.class);
                if (Build.VERSION.SDK_INT >= 31) {
                    out.put("key_security_level", keyInfo.getSecurityLevel());
                } else {
                    out.put("inside_secure_hardware", isInsideSecureHardwareCompat(keyInfo));
                }
            } catch (Throwable inner) {
                out.put("key_info_error", inner.getClass().getSimpleName());
            }

            ks = KeyStore.getInstance(KEYSTORE_PROVIDER);
            ks.load(null);
            Certificate[] chain = ks.getCertificateChain(alias);
            if (chain == null || chain.length == 0 || !(chain[0] instanceof X509Certificate)) {
                out.put("status", "missing_cert_chain");
                return out;
            }
            out.put("cert_chain_len", chain.length);
            X509Certificate leaf = (X509Certificate) chain[0];
            X509Certificate root = (X509Certificate) chain[chain.length - 1];
            out.put("root_subject", root.getSubjectX500Principal().getName());

            byte[] extBytes = leaf.getExtensionValue(ATTESTATION_OID);
            if (extBytes == null) {
                out.put("status", "missing_attestation_extension");
                return out;
            }
            parseKeyDescription(extBytes, out);
            out.put("status", "ok");
        } catch (ProviderException e) {
            putError(out, e);
        } catch (Throwable t) {
            putError(out, t);
        } finally {
            try {
                if (ks == null) {
                    ks = KeyStore.getInstance(KEYSTORE_PROVIDER);
                    ks.load(null);
                }
                if (ks.containsAlias(alias)) {
                    ks.deleteEntry(alias);
                }
            } catch (Throwable ignored) {}
        }
        return out;
    }

    private static void putError(JSONObject out, Throwable t) {
        try {
            out.put("status", "error");
            out.put("exception", t.getClass().getName());
            out.put("message", t.getMessage() != null ? t.getMessage() : "");
        } catch (Exception ignored) {}
    }

    private static void parseKeyDescription(byte[] extValue, JSONObject out) throws Exception {
        DerReader wrapper = new DerReader(extValue, 0, extValue.length);
        DerTlv octets = wrapper.next();
        if (octets.tagClass != 0 || octets.tagNumber != 4) {
            throw new IllegalArgumentException("expected OCTET_STRING wrapper");
        }
        DerReader seqReader = new DerReader(extValue, octets.valueOffset, octets.valueOffset + octets.valueLength);
        DerTlv keyDesc = seqReader.next();
        if (keyDesc.tagClass != 0 || keyDesc.tagNumber != 16 || !keyDesc.constructed) {
            throw new IllegalArgumentException("expected KeyDescription SEQUENCE");
        }
        DerReader fields = new DerReader(extValue, keyDesc.valueOffset, keyDesc.valueOffset + keyDesc.valueLength);
        DerTlv attVer = fields.next();
        DerTlv attSec = fields.next();
        DerTlv kmVer = fields.next();
        DerTlv kmSec = fields.next();
        fields.next(); // attestationChallenge
        fields.next(); // uniqueId
        DerTlv swEnforced = fields.next();
        DerTlv teeEnforced = fields.next();

        out.put("attestation_version", decodeInt(extValue, attVer));
        out.put("attestation_security_level", securityLevelName(decodeInt(extValue, attSec)));
        out.put("keymint_version", decodeInt(extValue, kmVer));
        out.put("keymint_security_level", securityLevelName(decodeInt(extValue, kmSec)));

        JSONObject rootOfTrust = findRootOfTrust(extValue, teeEnforced);
        String source = "teeEnforced";
        if (rootOfTrust == null) {
            rootOfTrust = findRootOfTrust(extValue, swEnforced);
            source = "softwareEnforced";
        }
        if (rootOfTrust != null) {
            rootOfTrust.put("source", source);
            out.put("root_of_trust", rootOfTrust);
        }
    }

    private static JSONObject findRootOfTrust(byte[] buf, DerTlv authList) throws Exception {
        if (!authList.constructed) {
            return null;
        }
        DerReader reader = new DerReader(buf, authList.valueOffset, authList.valueOffset + authList.valueLength);
        while (reader.hasRemaining()) {
            DerTlv entry = reader.next();
            if (entry.tagClass == 2 && entry.tagNumber == TAG_ROOT_OF_TRUST && entry.constructed) {
                DerReader wrap = new DerReader(buf, entry.valueOffset, entry.valueOffset + entry.valueLength);
                DerTlv rotSeq = wrap.next();
                DerReader rotFields = new DerReader(buf, rotSeq.valueOffset, rotSeq.valueOffset + rotSeq.valueLength);
                DerTlv bootKey = rotFields.next();
                DerTlv deviceLocked = rotFields.next();
                DerTlv verifiedBootState = rotFields.next();
                JSONObject rot = new JSONObject();
                rot.put("verified_boot_key_sha256", sha256Hex(buf, bootKey.valueOffset, bootKey.valueLength));
                rot.put("device_locked", deviceLocked.valueLength > 0 && buf[deviceLocked.valueOffset] != 0);
                int state = decodeInt(buf, verifiedBootState);
                rot.put("verified_boot_state", state);
                rot.put("verified_boot_state_name", verifiedBootStateName(state));
                if (rotFields.hasRemaining()) {
                    DerTlv bootHash = rotFields.next();
                    rot.put("verified_boot_hash_sha256", sha256Hex(buf, bootHash.valueOffset, bootHash.valueLength));
                }
                return rot;
            }
        }
        return null;
    }

    private static String securityLevelName(int lvl) {
        switch (lvl) {
            case 0: return "Software";
            case 1: return "TrustedEnvironment";
            case 2: return "StrongBox";
            default: return "Unknown(" + lvl + ")";
        }
    }

    private static String verifiedBootStateName(int state) {
        switch (state) {
            case 0: return "Verified";
            case 1: return "SelfSigned";
            case 2: return "Unverified";
            case 3: return "Failed";
            default: return "Unknown(" + state + ")";
        }
    }

    private static int decodeInt(byte[] buf, DerTlv tlv) {
        int val = 0;
        for (int i = 0; i < tlv.valueLength; i++) {
            val = (val << 8) | (buf[tlv.valueOffset + i] & 0xFF);
        }
        return val;
    }

    static String sha256Hex(byte[] data, int offset, int len) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(data, offset, len);
        byte[] digest = md.digest();
        StringBuilder sb = new StringBuilder(digest.length * 2);
        for (byte b : digest) {
            sb.append(String.format(Locale.ROOT, "%02x", b & 0xFF));
        }
        return sb.toString();
    }

    private static final class DerTlv {
        final int tagClass;
        final boolean constructed;
        final int tagNumber;
        final int valueOffset;
        final int valueLength;

        DerTlv(int tagClass, boolean constructed, int tagNumber, int valueOffset, int valueLength) {
            this.tagClass = tagClass;
            this.constructed = constructed;
            this.tagNumber = tagNumber;
            this.valueOffset = valueOffset;
            this.valueLength = valueLength;
        }
    }

    private static final class DerReader {
        private final byte[] buf;
        private final int limit;
        private int pos;

        DerReader(byte[] buf, int start, int limit) {
            this.buf = buf;
            this.pos = start;
            this.limit = limit;
        }

        boolean hasRemaining() {
            return pos < limit;
        }

        DerTlv next() {
            if (pos >= limit) {
                throw new IllegalArgumentException("DER underrun");
            }
            int first = buf[pos++] & 0xFF;
            int tagClass = (first >> 6) & 0x03;
            boolean constructed = (first & 0x20) != 0;
            int tagNumber = first & 0x1F;
            if (tagNumber == 0x1F) {
                tagNumber = 0;
                while (true) {
                    if (pos >= limit) {
                        throw new IllegalArgumentException("DER tag underrun");
                    }
                    int b = buf[pos++] & 0xFF;
                    tagNumber = (tagNumber << 7) | (b & 0x7F);
                    if ((b & 0x80) == 0) {
                        break;
                    }
                }
            }
            if (pos >= limit) {
                throw new IllegalArgumentException("DER len underrun");
            }
            int lenByte = buf[pos++] & 0xFF;
            int len;
            if ((lenByte & 0x80) == 0) {
                len = lenByte;
            } else {
                int numBytes = lenByte & 0x7F;
                if (numBytes == 0 || numBytes > 4 || pos + numBytes > limit) {
                    throw new IllegalArgumentException("DER bad length");
                }
                len = 0;
                for (int i = 0; i < numBytes; i++) {
                    len = (len << 8) | (buf[pos++] & 0xFF);
                }
            }
            if (len < 0 || pos + len > limit) {
                throw new IllegalArgumentException("DER value out of bounds");
            }
            int valueOffset = pos;
            pos += len;
            return new DerTlv(tagClass, constructed, tagNumber, valueOffset, len);
        }
    }
}
