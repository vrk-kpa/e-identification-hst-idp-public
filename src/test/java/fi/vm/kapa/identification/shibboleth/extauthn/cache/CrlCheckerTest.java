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

import com.google.common.cache.CacheBuilder;
import com.google.common.cache.LoadingCache;
import fi.vm.kapa.identification.shibboleth.extauthn.exception.CertificateStatusException;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import javax.security.auth.x500.X500Principal;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.InputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;

import static org.mockito.Matchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class CrlCheckerTest {

    private X509Certificate certificate;

    private X509Certificate iCAcertificate;

    private X509CRL crl;
    @Before
    public void setup() throws  Exception {
        ClassLoader classLoader = getClass().getClassLoader();

        File file = new File(classLoader.getResource("certs/test-cert.crt").getFile());
        InputStream in = new FileInputStream(file);
        CertificateFactory cf = CertificateFactory.getInstance("X509");
        certificate = (X509Certificate)cf.generateCertificate(in);

        File ica = new File(classLoader.getResource("certs/test-iCA.crt").getFile());
        InputStream ica_in = new FileInputStream(ica);
        CertificateFactory ica_cf = CertificateFactory.getInstance("X509");
        iCAcertificate = (X509Certificate)ica_cf.generateCertificate(ica_in);

        File crlFile = new File(classLoader.getResource("crls/test-crl.crl").getFile());
        InputStream crlIn = new FileInputStream(crlFile);
        CertificateFactory crl_cf = CertificateFactory.getInstance("X509");
        crl = (X509CRL)crl_cf.generateCRL(crlIn);
    }

    @Test
    public void crlCacheContainsCRLAfterFirstGet() throws Exception {

        X509CRL expectedValue = mock(X509CRL.class);

        CrlCacheLoader crlCacheLoader = mock(CrlCacheLoader.class);
        when(crlCacheLoader.load(any())).thenReturn(expectedValue);

        LoadingCache<X500Principal,X509CRL> crlLoadingCache = CacheBuilder.newBuilder()
                .maximumSize(1000)
                .expireAfterWrite(100, TimeUnit.MILLISECONDS)
                .build(crlCacheLoader);
        CrlChecker crlChecker = new CrlChecker(crlLoadingCache);

        crlChecker.verifyAndValidate(iCAcertificate, certificate);

        Assert.assertEquals(expectedValue, crlLoadingCache.get(certificate.getIssuerX500Principal()));
    }

    @Test
    public void crlCheckerReturnsCRLWhenCRLIsUpToDate() throws Exception {
        testUptodateCRL(-1);
    }

    @Test
    public void crlCheckerReturnsCRLWhenCRLJustUpToDate() throws Exception {
        testUptodateCRL(0);
    }

    @Test
    public void crlCheckerReturnCrlMissingWhenOutdatedCrlFound() throws Exception {
        try {
            testUptodateCRL(1);
            Assert.fail("No exception was thrown.");
        } catch (CertificateStatusException ste ) {
            Assert.assertEquals(CertificateStatusException.ErrorCode.CRL_MISSING, ste.getErrorCode());
        }
    }

    @Test
    public void testCrlCheckerThrowsCrlMissingException() throws Exception {

        LoadingCache loadingCache = mock(LoadingCache.class);
        when(loadingCache.get(any())).thenThrow(new ExecutionException("TEST", new FileNotFoundException()));

        CrlChecker crlChecker = new CrlChecker(loadingCache);

        try {
            crlChecker.verifyAndValidate(iCAcertificate, certificate);
            Assert.fail("No exception was thrown.");
        } catch (CertificateStatusException ste ) {
            Assert.assertEquals(CertificateStatusException.ErrorCode.CRL_MISSING, ste.getErrorCode());
        }
    }

    private void testUptodateCRL(long add) throws CertificateStatusException {
        Clock clock = mock(Clock.class);
        long crlMillis = crl.getNextUpdate().getTime();
        when(clock.millis()).thenReturn(crlMillis+add);

        LoadingCache<X500Principal,X509CRL> loadingCache =  CacheBuilder.newBuilder()
                .maximumSize(1000)
                .expireAfterWrite(10000, TimeUnit.MILLISECONDS)
                .build(new CrlCacheLoader("src/test/resources/crls", "1", clock));
        CrlChecker crlChecker = new CrlChecker(loadingCache);

        crlChecker.verifyAndValidate(iCAcertificate, certificate);
    }
}
