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

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import com.google.common.cache.LoadingCache;
import fi.vm.kapa.identification.shibboleth.extauthn.cache.CrlChecker;
import fi.vm.kapa.identification.shibboleth.extauthn.exception.CertificateStatusException;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import javax.security.auth.x500.X500Principal;

import static org.mockito.Matchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class CRLCheckTest {

    private String icaPath;
    private String caPath;

    @Before
    public void setup() {
        this.icaPath = "src/test/resources/certs";
        this.caPath = "src/test/resources/certs";
    }
        
    @Test
    public void testCertUtilHeaderToolOK() throws Exception {
        String certString = new String(Files.readAllBytes(Paths.get("src/test/resources/headertest/testinen.header")));
        X509Certificate cert = CertificateUtil.getCertFromHeader(certString);
        Assert.assertTrue(cert.getSubjectDN().getName().contains("Testinen"));
    }

    @Test
    public void testCRLUtilCRLCheckOK() throws Exception {
        ClassLoader classLoader = getClass().getClassLoader();
        File file = new File(classLoader.getResource("certs/test-cert.crt").getFile());
        InputStream in = new FileInputStream(file);
        CertificateFactory cf = CertificateFactory.getInstance("X509");
        X509Certificate certificate = (X509Certificate)cf.generateCertificate(in);

        boolean certOK = false;

        CrlChecker crlChecker = mock(CrlChecker.class);
        CertificateUtil crlUtil = new CertificateUtil(this.icaPath, this.caPath, crlChecker);

        if ( crlUtil.checkCertificateStatus(certificate) != null ) {
            certOK = true;
        }

        Assert.assertEquals(certOK, true);
    }

    @Test
    public void testCRLUtilCRLCheckCertificateRevoked() throws Exception {
        ClassLoader classLoader = getClass().getClassLoader();
        File file = new File(classLoader.getResource("certs/test-cert-revoked.crt").getFile());
        InputStream in = new FileInputStream(file);
        CertificateFactory cf = CertificateFactory.getInstance("X509");
        X509Certificate certificate = (X509Certificate)cf.generateCertificate(in);

        File crlFile = new File(classLoader.getResource("crls/crl.crt").getFile());
        InputStream crlIn = new FileInputStream(crlFile);
        CertificateFactory crl_cf = CertificateFactory.getInstance("X509");
        X509CRL crl = (X509CRL)crl_cf.generateCRL(crlIn);

        LoadingCache<X500Principal,X509CRL> crlLoadingCache = mock(LoadingCache.class);
        when(crlLoadingCache.get(any())).thenReturn(crl);
        
        CertificateStatusException.ErrorCode exceptionType = null;

        CrlChecker crlChecker = new CrlChecker(crlLoadingCache);
        CertificateUtil crlUtil = new CertificateUtil(this.icaPath, this.caPath, crlChecker);

        try {
            crlUtil.checkCertificateStatus(certificate);
        } catch (CertificateStatusException ste ) {
            exceptionType = ste.getErrorCode();
        }

        Assert.assertEquals(exceptionType, CertificateStatusException.ErrorCode.CERT_REVOKED);
    }

}
