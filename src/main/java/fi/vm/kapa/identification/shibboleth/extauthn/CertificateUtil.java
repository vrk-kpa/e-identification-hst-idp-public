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
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Date;

import javax.security.auth.x500.X500Principal;
import javax.servlet.http.HttpServletRequest;

import fi.vm.kapa.identification.shibboleth.extauthn.exception.CertificateStatusException;
import org.apache.commons.lang.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import static fi.vm.kapa.identification.shibboleth.extauthn.exception.CertificateStatusException.ErrorCode.*;

@Component
public class CertificateUtil {

    private static final Logger logger = LoggerFactory.getLogger(CertificateUtil.class);

    // intermediate certificate path
    private final String iCADirPath;

    // root CA directory path
    private final String caFilePath;

    // crl directory path
    private final String crlFilePath;

    // Conditional value for CRL updatetime verification
    private final String crlUpdatetimeValidation;
    
    // Certificate revocation list
    private X509CRL crl = null;

    //CA Certificate
    private X509Certificate CACert = null;

    private int certCounter = 0;

    public CertificateUtil(String icaPath,
                           String caPath,
                           String crlPath,
                           String crlUpdatetimeValidation) {
        this.iCADirPath = icaPath;
        this.caFilePath = caPath;
        this.crlFilePath = crlPath;
        this.crlUpdatetimeValidation = crlUpdatetimeValidation;
    }

    public X509Certificate getValidCertificate(HttpServletRequest httpRequest) throws CertificateStatusException {

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
        X509Certificate iCACert = getValidIntermediateCA(certificate);

        // 3) check certificate revocation list status
        X509CRL crl = getValidCRL(iCACert, certificate);

        // 4) check that certificate is not revoked and return
        if ( crl.isRevoked(certificate) ) {
            logger.warn("Certificate is in CRL: "+ Integer.toString(crl.hashCode()));
            throw new CertificateStatusException("Certificate is in CRL", CERT_REVOKED);
        } else {
            logger.info("Certificate not in CRL" + Integer.toString(crl.hashCode()));
        }

        return certificate;

    }

    private X509CRL getValidCRL(X509Certificate iCACert, X509Certificate certificate) throws CertificateStatusException {

        X509CRL revList = getCRLFromFile(crlFilePath, certificate.getIssuerX500Principal());

        //Cert is valid and trusted, proceed with CRL checks
        if ( revList == null ) {
            logger.error("Error loading CRL from path "+ crlFilePath);
            throw new CertificateStatusException("CRL is missing.", CRL_MISSING);
        }

        logger.info("CRL updatetime: "+ revList.getNextUpdate().toString());
        logger.info("Currenttime: "+ new Date(System.currentTimeMillis()));

        Date currentDate = new Date(System.currentTimeMillis() - 7200 * 1000);
        logger.info("Currenttime -2: "+ currentDate.toString());

        //Checking CRL updatetime validity
        if ( currentDate.after(revList.getNextUpdate()) ) {
            logger.error("Current CRL is outdated");
            if ( !"0".equals(crlUpdatetimeValidation)) {
                throw new CertificateStatusException("Current CRL is outdated.", CRL_OUTDATED);
            }
        }

        //Check CRL signature validity against intermediate CA
        try {
            revList.verify(iCACert.getPublicKey());
        } catch (Exception e) {
            logger.error("CRL signature is not valid", e);
            throw new CertificateStatusException("CRL signature is not valid.", CRL_SIGNATURE_FAILED);
        }
        return revList;
    }

    private X509Certificate getValidIntermediateCA(X509Certificate certificate) throws CertificateStatusException {

        //Check certificate signature validity against intermediate CA
        X500Principal principal = certificate.getIssuerX500Principal();
        X509Certificate iCACert = getCertFromFile(iCADirPath, principal);

        try {
            certificate.verify(iCACert.getPublicKey());
        } catch (Exception e) {
            logger.error("Certificate signature is not valid.");
            throw new CertificateStatusException("Certificate signature is not valid.", UNKNOWN_ICA);
        }

        //Check intermediate CA validity against root CA
        X509Certificate CACert = getCertFromFile(caFilePath, iCACert.getIssuerX500Principal());
        try {
            iCACert.verify(CACert.getPublicKey());
        } catch (Exception e) {
            logger.error("Intermediate CA-certificate signature is not valid.");
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
            logger.warn("Error getting client certificate from request header", e);
            return null;
        }
        return newCert;
    }

    private X509Certificate getCertFromFile(String certDirPath, X500Principal CAx500Principal) {
        CACert = null;
        certCounter = 0;
        try {
            Files.walk(Paths.get(certDirPath)).forEach(filePath -> {
                if (Files.isRegularFile(filePath)) {
                    try {
                        CertificateFactory cf = CertificateFactory.getInstance("X509");
                        FileInputStream inputStream = new FileInputStream(filePath.toString());
                        X509Certificate x509Certificate = (X509Certificate)cf.generateCertificate(inputStream);
                        if (x509Certificate.getSubjectX500Principal().equals(CAx500Principal) ) {
                            if ( certCounter++ > 1 ) {
                                throw new Exception("Critical error. Multiple CAs found in the file system.");
                            } else {
                                CACert = x509Certificate;
                            }
                        }
                    } catch (Exception e) {
                        logger.error("Reading certificate authority certificate "+ filePath.toString() +" from file system failed", e);
                    }
                }
            });
        } catch(Exception e) {
            logger.error("Certificate is unreadable");
        }
        return CACert;
    }

    private X509CRL getCRLFromFile(String crlDirPath, X500Principal CAx500Principal) {
        crl=null;
        try {
            Files.walk(Paths.get(crlDirPath)).forEach(filePath -> {
                if (Files.isRegularFile(filePath)) {
                    try {
                        CertificateFactory cf = CertificateFactory.getInstance("X509");
                        FileInputStream inputStream = new FileInputStream(filePath.toString());
                        X509CRL x509Crl=(X509CRL)cf.generateCRL(inputStream);
                        if (x509Crl.getIssuerX500Principal().equals(CAx500Principal) ) {
                            crl = x509Crl;
                        }
                    } catch (Exception e) {
                        logger.error("Reading CRL "+ filePath.toString() +" from filesystem failed", e);
                    }
                }
            });
        } catch(Exception e) {
            logger.error("CRL is unreadable");
        }

        return crl;
    }
}
