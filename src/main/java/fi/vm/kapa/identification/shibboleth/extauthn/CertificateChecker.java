/**
 * The MIT License
 * Copyright (c) 2015 Population Register Centre
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

package fi.vm.kapa.identification.shibboleth.extauthn;

import java.io.*;
import java.math.BigInteger;
import java.nio.file.*;
import java.security.cert.*;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import javax.security.auth.x500.X500Principal;

import fi.vm.kapa.identification.shibboleth.extauthn.cache.CrlChecker;
import fi.vm.kapa.identification.shibboleth.extauthn.context.AuditLoggerContext;
import fi.vm.kapa.identification.shibboleth.extauthn.exception.CertificateStatusException;
import org.apache.commons.lang.time.DateFormatUtils;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DEROctetString;
import org.cryptacular.x509.dn.NameReader;
import org.cryptacular.x509.dn.StandardAttributeType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import static fi.vm.kapa.identification.shibboleth.extauthn.exception.CertificateStatusException.ErrorCode.*;

@Component
public class CertificateChecker {

    private static final Logger logger = LoggerFactory.getLogger(CertificateChecker.class);

    private final Map<X500Principal, X509Certificate> caMap = new HashMap<>();
    private final Map<X500Principal, X509Certificate> icaMap = new HashMap<>();

    private final CrlChecker crlChecker;

    private final String CRL_NUMBER_OID = "2.5.29.20";

    private final String DATE_TIME_PATTERN = "yyyyMMdd'T'HHmmss'Z'";

    private AuditLoggerContext auditLoggerContext = null;

    public CertificateChecker(String icaPath,
                              String caPath,
                              CrlChecker crlChecker) {
        // initialize CA/iCA mappings
        initializeCertificateMap(caMap, caPath);
        initializeCertificateMap(icaMap, icaPath);
        this.crlChecker = crlChecker;
    }

    public X509Certificate checkCertificateStatus(X509Certificate certificate) throws CertificateStatusException {

        // 1) check if certificate is expired
        try {
            certificate.checkValidity();
        } catch (CertificateException ce) {
            logger.warn("Card certificate is expired.", ce);
            throw new CertificateStatusException("Card certificate is expired.", CERT_EXPIRED);
        }

        // 2) check certificate chain
        X509Certificate issuerCertificate = getValidIssuerCertificate(certificate);

        // 3) check certificate revocation list status
        try {
            crlChecker.verifyAndValidate(issuerCertificate, certificate);
            auditLoggerContext = initializeAuditLoggerContext(certificate, crlChecker.getCrl(), false);
        } catch (CertificateStatusException cse) {
            if ( cse.getErrorCode() == CertificateStatusException.ErrorCode.CERT_REVOKED ) {
                auditLoggerContext = initializeAuditLoggerContext(certificate, crlChecker.getCrl(), true);
            }
            throw cse;
        }

        return certificate;

    }

    private X509Certificate getValidIssuerCertificate(X509Certificate certificate) throws CertificateStatusException {

        // Check certificate signature validity against intermediate CA
        X509Certificate iCACert = icaMap.get(certificate.getIssuerX500Principal());

        try {
            certificate.verify(iCACert.getPublicKey());
        } catch (Exception e) {
            logger.warn("Certificate signature is not valid.", e);
            throw new CertificateStatusException("Certificate signature is not valid.", UNKNOWN_ICA);
        }

        // Check intermediate CA validity against root CA
        // Current implementation checks only two levels of certificate chain (cert -> iCA -> CA)!
        X509Certificate CACert = caMap.get(iCACert.getIssuerX500Principal());

        try {
            iCACert.verify(CACert.getPublicKey());
        } catch (Exception e) {
            logger.error("Intermediate CA-certificate signature is not valid.", e);
            throw new CertificateStatusException("Intermediate CA-certificate signature is not valid.", UNKNOWN_CA);
        }
        return iCACert;
    }

    private void initializeCertificateMap(final Map<X500Principal, X509Certificate> certMap, String certDirPath) {
        try {
            Files.walk(Paths.get(certDirPath)).filter(Files::isRegularFile).forEach(filePath -> {
                try {
                    CertificateFactory cf = CertificateFactory.getInstance("X509");
                    FileInputStream inputStream = new FileInputStream(filePath.toString());
                    X509Certificate x509Certificate = (X509Certificate) cf.generateCertificate(inputStream);
                    certMap.put(x509Certificate.getSubjectX500Principal(), x509Certificate);
                } catch ( Exception e ) {
                    logger.warn("Reading certificate authority certificate "+ filePath.toString() +" from file system failed", e);
                }
            });
        } catch(IOException ioe) {
            logger.error("Error reading ca/ica certificates from path " + certDirPath, ioe);
        }
    }

    private AuditLoggerContext initializeAuditLoggerContext(X509Certificate certificate, X509CRL crl, boolean isRevoked) {

        if ( Objects.isNull(certificate) || Objects.isNull(crl) ) {
            return null;
        }

        final String serialNumber = certificate.getSerialNumber().toString(16).toUpperCase();
        final String issuerCN = new NameReader(certificate).readIssuer().getValue(StandardAttributeType.CommonName);
        final String crlNumber = toHex(getCRLNumber(crl));
        final String lastUpdate = DateFormatUtils.format(crl.getThisUpdate(), DATE_TIME_PATTERN);

        return new AuditLoggerContext(serialNumber, crlNumber, issuerCN, lastUpdate, isRevoked);
    }

    private String getCRLNumber(X509CRL crl) {

        final byte[] encodedCrlNumber = crl.getExtensionValue(CRL_NUMBER_OID);
        String crlNumber = "";

        try {
            if (encodedCrlNumber != null) {
                ASN1Primitive derObject = toDERObject(encodedCrlNumber);
                if (derObject instanceof DEROctetString) {
                    DEROctetString derOctetString = (DEROctetString) derObject;

                    derObject = toDERObject(derOctetString.getOctets());
                    crlNumber = derObject.toString();
                } else {
                    logger.warn("CRL Number extraction failed");
                }
            } else {
                logger.warn("CRL Number extension not present");
            }
        } catch (IOException iex) {
            logger.warn("Exception while extracting CRL Number", iex);
        }

        return crlNumber;
    }

    private ASN1Primitive toDERObject(byte[] data) throws IOException {

        ByteArrayInputStream inStream = new ByteArrayInputStream(data);
        ASN1InputStream asnInputStream = new ASN1InputStream(inStream);

        return asnInputStream.readObject();
    }

    private String toHex(String str) {

        try {
            return String.format("%X", new BigInteger(str));
        } catch (NumberFormatException | NullPointerException ex) {
            logger.warn("Failed to convert crl number to hex format", ex);
        }

        return "";
    }

    public AuditLoggerContext getAuditLoggerContext() { return auditLoggerContext; }

}
