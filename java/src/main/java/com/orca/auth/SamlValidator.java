package com.orca.auth;

import java.io.*;
import java.security.*;
import java.security.cert.*;
import java.util.*;
import java.util.Base64;

/**
 * saml assertion validator for enterprise sso security auditing.
 * checks for common misconfigurations and vulnerabilities.
 */
public class SamlValidator {

    private final Map<String, X509Certificate> trustedIdps;
    private final List<String> findings;

    public SamlValidator() {
        this.trustedIdps = new HashMap<>();
        this.findings = new ArrayList<>();
    }

    public void addTrustedIdp(String entityId, X509Certificate cert) {
        trustedIdps.put(entityId, cert);
    }

    public List<String> validateAssertion(String samlResponse) {
        findings.clear();
        byte[] decoded;
        try {
            decoded = Base64.getDecoder().decode(samlResponse);
        } catch (IllegalArgumentException e) {
            findings.add("critical: invalid base64 encoding");
            return findings;
        }
        String xml = new String(decoded);
        checkSignature(xml);
        checkConditions(xml);
        checkEncryption(xml);
        checkReplayProtection(xml);
        return new ArrayList<>(findings);
    }

    private void checkSignature(String xml) {
        if (!xml.contains("SignatureValue")) {
            findings.add("critical: saml response is not signed");
        }
        if (xml.contains("SignatureMethod") && xml.contains("rsa-sha1")) {
            findings.add("warning: using sha1 signature (recommend sha256+)");
        }
    }

    private void checkConditions(String xml) {
        if (!xml.contains("Conditions")) {
            findings.add("warning: no conditions element - assertion never expires");
        }
        if (!xml.contains("NotOnOrAfter")) {
            findings.add("warning: no expiration set on assertion");
        }
        if (!xml.contains("AudienceRestriction")) {
            findings.add("warning: no audience restriction - assertion accepted by any sp");
        }
    }

    private void checkEncryption(String xml) {
        if (!xml.contains("EncryptedAssertion") && !xml.contains("EncryptedAttribute")) {
            findings.add("info: assertion is not encrypted (attributes visible in transit)");
        }
    }

    private void checkReplayProtection(String xml) {
        if (!xml.contains("InResponseTo")) {
            findings.add("warning: no InResponseTo - vulnerable to replay attacks");
        }
    }

    public List<String> auditSpMetadata(String metadataXml) {
        List<String> spFindings = new ArrayList<>();
        if (!metadataXml.contains("WantAssertionsSigned=\"true\"")) {
            spFindings.add("critical: sp does not require signed assertions");
        }
        if (metadataXml.contains("HTTP-Redirect") && metadataXml.contains("SingleLogoutService")) {
            spFindings.add("info: slo via redirect binding (consider post for security)");
        }
        if (!metadataXml.contains("KeyDescriptor")) {
            spFindings.add("warning: no encryption key in metadata");
        }
        return spFindings;
    }

    public Map<String, Object> summary() {
        Map<String, Object> summary = new HashMap<>();
        summary.put("trusted_idps", trustedIdps.size());
        summary.put("findings", findings.size());
        long critical = findings.stream().filter(f -> f.startsWith("critical")).count();
        long warnings = findings.stream().filter(f -> f.startsWith("warning")).count();
        summary.put("critical_count", critical);
        summary.put("warning_count", warnings);
        return summary;
    }

    public static void main(String[] args) {
        SamlValidator validator = new SamlValidator();
        System.out.println("saml validator initialized");
        System.out.println("trusted idps: " + validator.trustedIdps.size());
    }
}
