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
import com.google.common.cache.CacheLoader;
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
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;

import static org.mockito.Matchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class CrlCheckerTest {

    @Test
    public void crlCacheContainsCRLAfterFirstGet() throws Exception {

        ClassLoader classLoader = getClass().getClassLoader();

        File file = new File(classLoader.getResource("certs/test-cert.crt").getFile());
        InputStream in = new FileInputStream(file);
        CertificateFactory cf = CertificateFactory.getInstance("X509");
        X509Certificate certificate = (X509Certificate)cf.generateCertificate(in);

        File ica = new File(classLoader.getResource("certs/test-iCA.crt").getFile());
        InputStream ica_in = new FileInputStream(ica);
        CertificateFactory ica_cf = CertificateFactory.getInstance("X509");
        X509Certificate iCAcertificate = (X509Certificate)ica_cf.generateCertificate(ica_in);
        X509CRL expectedValue = mock(X509CRL.class);

        LoadingCache<X500Principal,X509CRL> crlLoadingCache = CacheBuilder.newBuilder()
                .maximumSize(1000)
                .expireAfterWrite(100, TimeUnit.MILLISECONDS)
                .build(
                        new CacheLoader<X500Principal,X509CRL>() {
                            public X509CRL load(X500Principal principal) throws Exception {
                                return expectedValue;
                            }
                        });
        CrlChecker crlChecker = new CrlChecker(crlLoadingCache);

        crlChecker.verifyAndValidate(iCAcertificate, certificate);

        Assert.assertEquals(expectedValue, crlLoadingCache.get(certificate.getIssuerX500Principal()));
    }

    @Test(expected = CertificateStatusException.class)
    public void crlCheckerThrowsExceptionWhenCrLNotFound() throws Exception {

        ClassLoader classLoader = getClass().getClassLoader();

        File file = new File(classLoader.getResource("certs/test-cert.crt").getFile());
        InputStream in = new FileInputStream(file);
        CertificateFactory cf = CertificateFactory.getInstance("X509");
        X509Certificate certificate = (X509Certificate)cf.generateCertificate(in);

        File ica = new File(classLoader.getResource("certs/test-iCA.crt").getFile());
        InputStream ica_in = new FileInputStream(ica);
        CertificateFactory ica_cf = CertificateFactory.getInstance("X509");
        X509Certificate iCAcertificate = (X509Certificate)ica_cf.generateCertificate(ica_in);


        LoadingCache loadingCache = mock(LoadingCache.class);
        CrlChecker crlChecker = new CrlChecker(loadingCache);
        when(loadingCache.get(any())).thenThrow(new ExecutionException("TEST", new FileNotFoundException()));
        crlChecker.verifyAndValidate(iCAcertificate, certificate);
    }
}
