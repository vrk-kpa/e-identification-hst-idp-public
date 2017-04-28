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
import java.nio.file.*;
import java.security.cert.*;
import java.util.HashMap;
import java.util.Map;
import javax.security.auth.x500.X500Principal;
import javax.servlet.http.HttpServletRequest;

import fi.vm.kapa.identification.shibboleth.extauthn.cache.CrlChecker;
import fi.vm.kapa.identification.shibboleth.extauthn.exception.CertificateStatusException;
import org.apache.commons.lang.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import static fi.vm.kapa.identification.shibboleth.extauthn.exception.CertificateStatusException.ErrorCode.*;

@Component
public class CertificateUtil {

    private static final Logger logger = LoggerFactory.getLogger(CertificateUtil.class);

    private final Map<X500Principal, X509Certificate> caMap = new HashMap<>();
    private final Map<X500Principal, X509Certificate> icaMap = new HashMap<>();

    private final CrlChecker crlChecker;

    public CertificateUtil(String icaPath,
                           String caPath,
                           CrlChecker crlChecker) {
        // initialize CA/iCA mappings
        initializeCertificateMap(caMap, caPath);
        initializeCertificateMap(icaMap, icaPath);
        this.crlChecker = crlChecker;
    }

    X509Certificate getValidCertificate(HttpServletRequest httpRequest) throws CertificateStatusException {

        String header = httpRequest.getHeader("SSL_CLIENT_CERT");

        X509Certificate newCert = getCertFromHeader(header);

        if ( newCert == null || !"SUCCESS".equalsIgnoreCase(httpRequest.getHeader("SSL_CLIENT_VERIFY"))) {
            logger.warn("No valid X.509 certificates found in request");
            throw new CertificateStatusException("No valid X.509 certificates found in request", NO_CERT_FOUND);
        }

        return checkCertificateStatus(newCert);
    }

    X509Certificate checkCertificateStatus(X509Certificate certificate) throws CertificateStatusException {

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
        crlChecker.verifyAndValidate(issuerCertificate, certificate);

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

    static X509Certificate getCertFromHeader(String certHeader) {
        X509Certificate newCert = null;
        try {
            //Add \r after cert header field, Cert API needs this
            String certHeaderWithCR = certHeader.replaceFirst("-----BEGIN CERTIFICATE-----", "-----BEGIN CERTIFICATE-----\r");
            if (StringUtils.isNotBlank(certHeaderWithCR)) {
                InputStream in = new ByteArrayInputStream(certHeaderWithCR.getBytes());
                CertificateFactory cf = CertificateFactory.getInstance("X.509");
                newCert = (X509Certificate)cf.generateCertificate(in);
            }
        } catch (final CertificateException e) {
            logger.warn("Getting client certificate from request header failed", e);
            return null;
        }
        return newCert;
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
}
