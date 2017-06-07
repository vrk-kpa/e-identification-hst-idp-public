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

package fi.vm.kapa.identification.shibboleth.extauthn.util;

import org.apache.commons.lang.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.security.Signature;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;


public class CertificateUtil {

    private static final Logger logger = LoggerFactory.getLogger(CertificateUtil.class);

    private static final String X509_PEM_HEADER = "-----BEGIN CERTIFICATE-----";
    private static final String X509_PEM_FOOTER = "-----END CERTIFICATE-----";

    public static X509Certificate getCertificate(String pemCertificate)
    {
        X509Certificate newCert = null;
        try {
            // Add \r after cert header field, Cert API needs this (Legacy method, Apache2-provided cert)
            pemCertificate = pemCertificate.replaceFirst(X509_PEM_HEADER, X509_PEM_HEADER + "\r");

            // Add X509 header and footer, Cert API needs this (SCS method, SCS-provided certificate)
            if (!pemCertificate.contains(X509_PEM_HEADER)) {
                pemCertificate = X509_PEM_HEADER + "\r" + pemCertificate + "\r" + X509_PEM_FOOTER;
            }

            if (StringUtils.isNotBlank(pemCertificate)) {
                InputStream in = new ByteArrayInputStream(pemCertificate.getBytes());
                CertificateFactory cf = CertificateFactory.getInstance("X.509");
                newCert = (X509Certificate)cf.generateCertificate(in);
            }
        } catch (final CertificateException|NullPointerException e) {
            logger.warn("Error getting client certificate from request", e);
        }
        return newCert;
    }

    // data = Base64-encoded original data of which the signature was generated
    // signature = Base64-encoded signature of SHA-256(data)
    // cert = certificate to check signature against
    public static boolean checkSignature(String data, String signature, X509Certificate cert)
    {
        boolean result = false;
        try {
            logger.debug("checkSignature: data={}, signature={}, cert={}", data, signature, cert.toString());
            byte[] sigToVerify = Base64.getDecoder().decode(signature);
            Signature sig = Signature.getInstance("SHA256withRSA");
            sig.initVerify(cert);
            sig.update(Base64.getDecoder().decode(data));
            result = sig.verify(sigToVerify);
        }
        catch (Exception e)
        {
            logger.warn("checkSignature: Got exception "+e.getClass(), e);
        }
        return result;
    }
}
