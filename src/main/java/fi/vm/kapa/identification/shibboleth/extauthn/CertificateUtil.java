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

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Date;

import javax.security.auth.x500.X500Principal;

import net.shibboleth.idp.authn.ExternalAuthenticationException;

import org.apache.commons.lang.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class CertificateUtil {

    private final static Logger logger = LoggerFactory.getLogger(CertificateUtil.class);

    //intermediate certificate path
    private String iCADirPath;

    //root CA directory path
    private String CAFilePath;

    //crl directory path
    private String crlFilePath;

    //Conditional value for CRL updatetime verification
    private String crlUpdatetimeValidation;
    
    //CRL 
    private X509CRL crl = null;

    //client certificate from electronic identifier card
    private final X509Certificate cert;

    //CA Certificate
    private X509Certificate CACert = null;

    private int certCounter = 0;

    public CertificateUtil(X509Certificate cert, String icaPath, String caPath, String crlPath, String crlUpdatetimeValidation) {
        this.iCADirPath = icaPath;
        this.CAFilePath = caPath;
        this.crlFilePath = crlPath;
        this.cert = cert;
        this.crlUpdatetimeValidation = crlUpdatetimeValidation;
    }

    public boolean checkCertificateStatus() throws ExternalAuthenticationException  {

        boolean crlCheckResult = false;

        try {

            //Check client certificate validity
            try {
                cert.checkValidity();
            } catch (CertificateException ce) {
                logger.warn("Card certificate is not valid");
                return false;
            }

            //Check certificate signature validity against intermediate CA
            X500Principal principal = cert.getIssuerX500Principal();
            X509Certificate iCACert = getCertFromFile(iCADirPath, principal);
            try {
                cert.verify(iCACert.getPublicKey());
            } catch (Exception e) {
                logger.error("Certificate signature is not valid");
                return false;
            }

            //Check intermediate CA validity against root CA
            X509Certificate CACert = getCertFromFile(CAFilePath, iCACert.getIssuerX500Principal());
            try {
                iCACert.verify(CACert.getPublicKey());
            } catch (Exception e) {
                logger.error("Intermediate CA-certificate signature is not valid");
                return false;
            }

            //Cert is valid and trusted, proceed with CRL checks
            X509CRL crl = getCRLFromFile(crlFilePath, cert.getIssuerX500Principal());
            if ( crl == null ) {
                logger.error("Error loading CRL from path "+ crlFilePath);
                return false;
            }

            logger.info("CRL updatetime: "+ crl.getNextUpdate().toString());
            logger.info("Currenttime: "+ new Date(System.currentTimeMillis()));
                   
            Date currentDate = new Date(System.currentTimeMillis() - 7200 * 1000);
            logger.info("Currenttime -2: "+ currentDate.toString());
           
            //Checking CRL updatetime validity
            if ( currentDate.after(crl.getNextUpdate()) ) {
                logger.error("Current CRL is outdated");
                if ( !crlUpdatetimeValidation.equals("0") ) {
                    throw new ExternalAuthenticationException();
                }
            }

            //Check CRL signature validity against intermediate CA
            try {
                crl.verify(iCACert.getPublicKey());
            } catch (Exception e) {
                logger.error("CRL signature is not valid");
                return false;
            }

            //Check if client certificate is in CRL
            if ( crl.isRevoked(cert) ) {
                logger.warn("Certificate is in CRL: "+ Integer.toString(crl.hashCode()));
                return false;
            } else {
                logger.info("Certificate not in CRL" + Integer.toString(crl.hashCode()));
            }

            //If no exceptions CRL check ok. All checks must be declared before this
            crlCheckResult = true;
        } catch (ExternalAuthenticationException eae) {
            throw new ExternalAuthenticationException("CRL list update failed within required time interval", eae);
        
        } catch (Exception ex) {
            logger.error("Verifying CRL failed", ex);
            crlCheckResult = false;
        }
        return crlCheckResult;
    }

    public static X509Certificate getCertFromHeader(String certHeader) {
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
                        logger.error("Reading certificate authority certificate "+ filePath.toString() +"from file system failed", e);
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
                        logger.error("Reading CRL "+ filePath.toString() +"from filesystem failed", e);
                    }
                }
            });
        } catch(Exception e) {
            logger.error("CRL is unreadable");
        }

        return crl;
    }
}
