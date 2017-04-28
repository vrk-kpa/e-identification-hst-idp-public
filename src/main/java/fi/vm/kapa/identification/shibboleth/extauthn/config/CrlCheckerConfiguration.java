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
package fi.vm.kapa.identification.shibboleth.extauthn.config;

import com.google.common.cache.CacheBuilder;
import com.google.common.cache.CacheLoader;
import com.google.common.cache.LoadingCache;
import fi.vm.kapa.identification.shibboleth.extauthn.cache.CrlChecker;
import fi.vm.kapa.identification.shibboleth.extauthn.cache.CrlFileVisitor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import javax.annotation.Nonnull;
import javax.security.auth.x500.X500Principal;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.cert.X509CRL;
import java.util.concurrent.TimeUnit;

@Configuration
public class CrlCheckerConfiguration {
    private static final Logger logger = LoggerFactory.getLogger(CrlCheckerConfiguration.class);

    @Value("${crl.cache.expiration.time}")
    private int crlCacheExpiration;

    @Value("${crl.dir.path}")
    private String crlPath;

    // Conditional value for CRL updatetime verification
    @Value("${crl.updatetime.validation}")
    private String crlUpdateTimeValidation;


    private CacheLoader provideCacheLoader(final String crlUpdateTimeValidation, final String crlPath) {
        return new CacheLoader<X500Principal,X509CRL>() {
            public X509CRL load(@Nonnull X500Principal principal) throws Exception {
                logger.debug("CRL not in cache or cache is expired, reloading for principal " + principal.toString());
                // find crl recursively and return first found
                CrlFileVisitor visitor = new CrlFileVisitor(principal, crlUpdateTimeValidation);
                Files.walkFileTree(Paths.get(crlPath), visitor);
                return visitor.getCRL();
            }
        };
    }

    @Bean
    LoadingCache provideCacheImplementation() {
        return CacheBuilder.newBuilder()
                .maximumSize(1000)
                .expireAfterWrite(crlCacheExpiration, TimeUnit.MILLISECONDS)
                .build(provideCacheLoader(crlUpdateTimeValidation, crlPath));
    }

    @Bean(name = "crlChecker")
    CrlChecker provideCrlChecker() {
        return new CrlChecker(provideCacheImplementation());
    }

}
