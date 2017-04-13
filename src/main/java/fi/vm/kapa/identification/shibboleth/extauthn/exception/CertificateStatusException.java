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

package fi.vm.kapa.identification.shibboleth.extauthn.exception;

public class CertificateStatusException extends Exception {

    public enum ErrorCode {
        NO_CERT_FOUND("2"),
        CERT_REVOKED("3"),
        CERT_TYPE_NOT_SUPPORTED("4"),
        VARTTI_SERVICE_ERROR("5"),
        INTERNAL_ERROR("6"),
        CERT_EXPIRED("7"),
        UNKNOWN_CA("8"),
        UNKNOWN_ICA("9"),
        CRL_OUTDATED("10"),
        CRL_MISSING("11"),
        CRL_SIGNATURE_FAILED("12");

        private String code;

        ErrorCode(String code) {
            this.code = code;
        }

        public String getCode() { return code; }
    }

    private final ErrorCode errorCode;

    public CertificateStatusException(String reason, ErrorCode code) {
        super(reason);
        errorCode = code;
    }

    public ErrorCode getErrorCode() {
        return errorCode;
    }
}
