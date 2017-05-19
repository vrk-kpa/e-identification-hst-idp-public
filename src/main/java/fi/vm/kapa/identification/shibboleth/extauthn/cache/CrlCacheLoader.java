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

import com.google.common.cache.CacheLoader;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nonnull;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.cert.X509CRL;
import java.time.Clock;
import javax.security.auth.x500.X500Principal;

public class CrlCacheLoader extends CacheLoader<X500Principal, X509CRL> {

    private static final Logger logger = LoggerFactory.getLogger(CrlCacheLoader.class);

    private final String crlPath;
    private final String crlUpdateTimeValidation;
    private final Clock clock;

    CrlCacheLoader(String crlPath, String crlUpdateTimeValidation, Clock clock) {
        this.crlPath = crlPath;
        this.crlUpdateTimeValidation = crlUpdateTimeValidation;
        this.clock = clock;
    }

    public CrlCacheLoader(String crlPath, String crlUpdateTimeValidation) {
        this(crlPath, crlUpdateTimeValidation, Clock.systemUTC());
    }

    public X509CRL load(@Nonnull X500Principal principal) throws Exception {
        logger.debug("CRL not in cache or cache is expired, reloading for principal " + principal.toString());
        // find crl recursively and return first found
        CrlFileVisitor visitor = new CrlFileVisitor(principal, crlUpdateTimeValidation, clock);
        Files.walkFileTree(Paths.get(crlPath), visitor);
        return visitor.getCRL();
    }
}
