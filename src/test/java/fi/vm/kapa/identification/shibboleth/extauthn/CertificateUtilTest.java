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

import com.google.common.cache.LoadingCache;
import fi.vm.kapa.identification.shibboleth.extauthn.cache.CrlChecker;
import fi.vm.kapa.identification.shibboleth.extauthn.exception.CertificateStatusException;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import javax.security.auth.x500.X500Principal;
import javax.servlet.http.HttpServletRequest;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;

import static org.mockito.Matchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class CertificateUtilTest {

    private String icaPath;
    private String caPath;

    private String assertFailMessage;

    private CertificateUtil certificateUtil;

    @Rule
    public TemporaryFolder tempFolder = new TemporaryFolder();

    @Before
    public void setup() throws Exception {
        this.icaPath = "src/test/resources/certs";
        this.caPath = "src/test/resources/certs";
        this.assertFailMessage = "No exception was thrown.";
        this.certificateUtil = new CertificateUtil(icaPath, caPath, mock(CrlChecker.class));

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

        CrlChecker crlChecker = provideCrlChecker();

        CertificateUtil certUtil = new CertificateUtil(this.icaPath, this.caPath, crlChecker);

        X509Certificate validCertificate = certUtil.checkCertificateStatus(certificate);

        Assert.assertNotNull(validCertificate);
    }

    @Test
    public void testCRLUtilCRLCheckCertificateRevoked() throws Exception {
        ClassLoader classLoader = getClass().getClassLoader();
        File file = new File(classLoader.getResource("certs/test-cert-revoked.crt").getFile());
        InputStream in = new FileInputStream(file);
        CertificateFactory cf = CertificateFactory.getInstance("X509");
        X509Certificate certificate = (X509Certificate)cf.generateCertificate(in);

        CrlChecker crlChecker = provideCrlChecker();
        CertificateUtil certUtil = new CertificateUtil(this.icaPath, this.caPath, crlChecker);

        try {
            certUtil.checkCertificateStatus(certificate);
            Assert.fail(assertFailMessage);
        } catch (CertificateStatusException ste ) {
            Assert.assertEquals(CertificateStatusException.ErrorCode.CERT_REVOKED, ste.getErrorCode());
        }
    }

    @Test
    public void testExpiredCertReturnsExpiredException() throws Exception {

        String testCert = new String(Files.readAllBytes(Paths.get("src/test/resources/headertest/testinen.header")));

        HttpServletRequest request = getValidRequestMock(testCert);

        try {
            certificateUtil.getValidCertificate(request);
            Assert.fail(assertFailMessage);
        } catch (CertificateStatusException ste ) {
            Assert.assertEquals(CertificateStatusException.ErrorCode.CERT_EXPIRED, ste.getErrorCode());
        }
    }

    @Test
    public void testCertUtilVerifyFailReturnsNotFoundException() throws Exception {

        String testCert = new String(Files.readAllBytes(Paths.get("src/test/resources/headertest/testinen.header")));

        HttpServletRequest request = getValidRequestMock(testCert);
        when(request.getHeader("SSL_CLIENT_VERIFY")).thenReturn("");

        try {
            certificateUtil.getValidCertificate(request);
            Assert.fail(assertFailMessage);
        } catch (CertificateStatusException ste ) {
            Assert.assertEquals(CertificateStatusException.ErrorCode.NO_CERT_FOUND, ste.getErrorCode());
        }
    }

    @Test
    public void testCertUtilUnknownCAReturnsUnknownCAException() throws Exception {


        String validCert = new String(Files.readAllBytes(Paths.get("src/test/resources/certs/test-cert.crt")));

        HttpServletRequest request = getValidRequestMock(validCert);

        // temporary empty folder that represents empty CA-folder
        File folder = tempFolder.newFolder();

        CertificateUtil certUtil = new CertificateUtil(icaPath, folder.getCanonicalPath(), mock(CrlChecker.class));

        try {
            certUtil.getValidCertificate(request);
            Assert.fail(assertFailMessage);
        } catch (CertificateStatusException ste ) {
            Assert.assertEquals(CertificateStatusException.ErrorCode.UNKNOWN_CA, ste.getErrorCode());
        }
    }

    @Test
    public void testCertUtilUnknownICAReturnsUnknownICAException() throws Exception {
        String validCert = new String(Files.readAllBytes(Paths.get("src/test/resources/certs/test-cert.crt")));

        HttpServletRequest request = getValidRequestMock(validCert);

        // temporary empty folder that represents empty iCA-folder
        File folder = tempFolder.newFolder();

        CertificateUtil certUtil = new CertificateUtil(folder.getCanonicalPath(), caPath, mock(CrlChecker.class));

        try {
            certUtil.getValidCertificate(request);
            Assert.fail(assertFailMessage);
        } catch (CertificateStatusException ste ) {
            Assert.assertEquals(CertificateStatusException.ErrorCode.UNKNOWN_ICA, ste.getErrorCode());
        }
    }

    private HttpServletRequest getValidRequestMock(String cert) {
        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getHeader("SSL_CLIENT_CERT")).thenReturn(cert);
        when(request.getHeader("SSL_CLIENT_VERIFY")).thenReturn("SUCCESS");
        return request;
    }

    private CrlChecker provideCrlChecker() throws Exception {

        ClassLoader classLoader = getClass().getClassLoader();
        File crlFile = new File(classLoader.getResource("crls/test-crl.crl").getFile());
        InputStream crlIn = new FileInputStream(crlFile);
        CertificateFactory crl_cf = CertificateFactory.getInstance("X509");
        X509CRL crl = (X509CRL)crl_cf.generateCRL(crlIn);

        LoadingCache<X500Principal,X509CRL> crlLoadingCache = mock(LoadingCache.class);
        when(crlLoadingCache.get(any())).thenReturn(crl);

        return new CrlChecker(crlLoadingCache);
    }
}
