package threat.pptx;

import threat.common.FindingClassification;
import threat.common.SecurityAnalyzer;
import threat.common.SecurityFinding;
import threat.common.ThreatSeverity;
import threat.common.ThreatType;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class PayloadFingerprint {

    public static class Fingerprint {

        private final int size;
        private final String sha256;

        public Fingerprint(
                int size,
                String sha256) {

            this.size = size;
            this.sha256 = sha256;
        }

        public int getSize() {
            return size;
        }

        public String getSha256() {
            return sha256;
        }
    }


    /**
     * Creates a SHA-256 fingerprint of the
     * supplied payload.
     *
     * The payload is never executed or written
     * to disk.
     */
    public Fingerprint fingerprint(
            byte[] payload) {

        if (payload == null) {

            return new Fingerprint(
                    0,
                    ""
            );
        }


        try {

            MessageDigest digest =
                    MessageDigest.getInstance(
                            "SHA-256"
                    );


            byte[] hash =
                    digest.digest(payload);


            return new Fingerprint(
                    payload.length,
                    toHex(hash)
            );


        } catch (NoSuchAlgorithmException e) {

            /*
             * SHA-256 is required by every standard
             * Java runtime, so this represents a
             * runtime/environment failure.
             */
            throw new IllegalStateException(
                    "SHA-256 is unavailable",
                    e
            );
        }
    }


    private String toHex(
            byte[] bytes) {

        StringBuilder result =
                new StringBuilder(
                        bytes.length * 2
                );


        for (byte value : bytes) {

            result.append(
                    String.format(
                            "%02x",
                            value & 0xff
                    )
            );
        }


        return result.toString();
    }
}