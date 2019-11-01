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

package fi.vm.kapa.identification.shibboleth.extauthn.context;

import org.opensaml.messaging.context.BaseContext;

public class AuditLoggerContext extends BaseContext {

    private final String serialNumber;

    private final String crlNumber;

    private final String issuerCN;

    private final String lastUpdate;

    private final boolean isRevoked;

    public AuditLoggerContext(String serialNumber, String crlNumber, String issuerCN, String lastUpdate, boolean isRevoked) {
         this.serialNumber = serialNumber;
         this.crlNumber = crlNumber;
         this.issuerCN = issuerCN;
         this.lastUpdate = lastUpdate;
         this.isRevoked = isRevoked;
    }

    public String getSerialNumber() {
        return serialNumber;
    }

    public String getCRLNumber() {
        return crlNumber;
    }

    public String getIssuerCN() {
        return issuerCN;
    }

    public String getLastUpdate() {
        return lastUpdate;
    }

    public boolean isRevoked() {
        return isRevoked;
    }

}
