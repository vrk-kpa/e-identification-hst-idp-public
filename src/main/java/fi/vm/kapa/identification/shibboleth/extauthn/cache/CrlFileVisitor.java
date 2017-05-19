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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.security.auth.x500.X500Principal;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.file.FileVisitResult;
import java.nio.file.Path;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.time.Clock;
import java.util.Date;

import static java.nio.file.FileVisitResult.CONTINUE;
import static java.nio.file.FileVisitResult.TERMINATE;

public class CrlFileVisitor extends SimpleFileVisitor<Path> {

    private static final Logger logger = LoggerFactory.getLogger(CrlFileVisitor.class);

    private X509CRL crl = null;

    private final X500Principal principal;

    private final String crlUpdatetimeValidation;

    private final Clock clock;

    CrlFileVisitor(X500Principal principal, String crlUpdatetimeValidation, Clock clock) {
        this.principal = principal;
        this.crlUpdatetimeValidation = crlUpdatetimeValidation;
        this.clock = clock;
    }

    X509CRL getCRL() {
        return this.crl;
    }

    @Override
    public FileVisitResult visitFile(Path filePath, BasicFileAttributes basicFileAttributes) throws IOException {
        if (basicFileAttributes.isRegularFile()) {
            try {
                CertificateFactory cf = CertificateFactory.getInstance("X509");
                FileInputStream inputStream = new FileInputStream(filePath.toString());
                X509CRL x509Crl=(X509CRL)cf.generateCRL(inputStream);
                if (x509Crl.getIssuerX500Principal().equals(principal) ) {
                    // Check CRL updatetime validity
                    if ( new Date(clock.millis()).after(x509Crl.getNextUpdate()) ) {
                        if ( "0".equals(crlUpdatetimeValidation) ) {
                            // return valid but expired CRL if up to date not found, for testing purposes only!
                            crl = x509Crl;
                        }
                        logger.warn("Found outdated CRL (" + filePath.toString() + ")");
                    }
                    else {
                        // return valid and up to date CRL
                        crl = x509Crl;
                        return TERMINATE;
                    }
                }
            } catch (Exception e) {
                logger.error("Reading CRL "+ filePath.toString() +" from filesystem failed", e);
            }
        }
        return CONTINUE;
    }

    @Override
    public FileVisitResult visitFileFailed(Path filePath, IOException ioException) {
        logger.warn("Reading certificate authority certificate "+ filePath.toString() +" from file system failed", ioException);
        return CONTINUE;
    }
}
