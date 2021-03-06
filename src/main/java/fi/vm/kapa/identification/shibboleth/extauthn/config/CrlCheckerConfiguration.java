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
import com.google.common.cache.LoadingCache;
import fi.vm.kapa.identification.shibboleth.extauthn.cache.CrlCacheLoader;
import fi.vm.kapa.identification.shibboleth.extauthn.cache.CrlChecker;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.concurrent.TimeUnit;

@Configuration
public class CrlCheckerConfiguration {

    @Value("${crl.cache.expiration.time}")
    private int crlCacheExpiration;

    @Value("${crl.dir.path}")
    private String crlPath;

    // Conditional value for CRL updatetime verification
    @Value("${crl.updatetime.validation}")
    private String crlUpdateTimeValidation;

    @Bean
    LoadingCache provideCacheImplementation() {
        return CacheBuilder.newBuilder()
                .maximumSize(1000)
                .expireAfterWrite(crlCacheExpiration, TimeUnit.MILLISECONDS)
                .build(new CrlCacheLoader(crlPath, crlUpdateTimeValidation));
    }

    @Bean(name = "crlChecker")
    CrlChecker provideCrlChecker() {
        return new CrlChecker(provideCacheImplementation());
    }

}
