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
package fi.vm.kapa.identification.shibboleth.extauthn.cache;

import com.google.common.cache.LoadingCache;
import fi.vm.kapa.identification.shibboleth.extauthn.exception.CertificateStatusException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import javax.annotation.Nonnull;
import javax.security.auth.x500.X500Principal;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;

import static fi.vm.kapa.identification.shibboleth.extauthn.exception.CertificateStatusException.ErrorCode.CERT_REVOKED;
import static fi.vm.kapa.identification.shibboleth.extauthn.exception.CertificateStatusException.ErrorCode.CRL_MISSING;
import static fi.vm.kapa.identification.shibboleth.extauthn.exception.CertificateStatusException.ErrorCode.CRL_SIGNATURE_FAILED;

@Component
public class CrlChecker {

    private static final Logger logger = LoggerFactory.getLogger(CrlChecker.class);


    private final LoadingCache<X500Principal, X509CRL> cache;

    @Autowired
    public CrlChecker(LoadingCache<X500Principal,X509CRL> loadingCache) {
        this.cache  = loadingCache;
    }

    @Nonnull
    private X509CRL getCRL(@Nonnull X500Principal principal) throws CertificateStatusException {
        try {
            return cache.get(principal);
        } catch (Exception e) {
            logger.error("Error loading CRL");
            throw new CertificateStatusException("CRL is missing.", CRL_MISSING);
        }
    }

    @Nonnull
    public X509CRL verifyAndValidate(X509Certificate iCACert, X509Certificate certificate) throws CertificateStatusException {

        X509CRL crl = getCRL(certificate.getIssuerX500Principal());

        //Check CRL signature validity against intermediate CA
        try {
            crl.verify(iCACert.getPublicKey());
        } catch (Exception e) {
            logger.error("CRL signature is not valid", e);
            throw new CertificateStatusException("CRL signature is not valid.", CRL_SIGNATURE_FAILED);
        }
        
        
        if ( crl.isRevoked(certificate) ) {
            logger.warn("Certificate is in CRL: "+ Integer.toString(crl.hashCode()));
            throw new CertificateStatusException("Certificate is in CRL", CERT_REVOKED);
        } else {
            logger.info("Certificate not in CRL" + Integer.toString(crl.hashCode()));
        }

        return crl;
    }

}
