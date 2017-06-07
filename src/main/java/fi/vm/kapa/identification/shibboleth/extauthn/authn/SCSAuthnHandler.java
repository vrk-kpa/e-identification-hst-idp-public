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

package fi.vm.kapa.identification.shibboleth.extauthn.authn;

import fi.vm.kapa.identification.shibboleth.extauthn.exception.CertificateStatusException;
import fi.vm.kapa.identification.shibboleth.extauthn.util.CertificateUtil;
import org.apache.commons.lang.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import java.security.cert.X509Certificate;

import static fi.vm.kapa.identification.shibboleth.extauthn.exception.CertificateStatusException.ErrorCode.NO_CERT_FOUND;
import static fi.vm.kapa.identification.shibboleth.extauthn.exception.CertificateStatusException.ErrorCode.SCS_SIGNATURE_FAILED;

@Component
public class SCSAuthnHandler extends AbstractAuthnHandler {

    @Autowired
    public SCSAuthnHandler(@Value("${oc.ca.orgname.set}") String organizationCardCA,
                           @Value("${hst.ca.orgname.set}") String hstCardCA)
    {
        super(organizationCardCA, hstCardCA);
    }

    @Override
    public X509Certificate getUserCertificate(HttpServletRequest httpRequest) throws CertificateStatusException
    {
        X509Certificate certificate = CertificateUtil.getCertificate(httpRequest.getParameter("scs_cert"));
        if (certificate == null) {
            throw new CertificateStatusException("No valid X.509 certificates found in request", NO_CERT_FOUND);
        }

        // Check signature (original data in HTTP session)
        HttpSession session = httpRequest.getSession();
        String data = (String)session.getAttribute("scs_data");
        session.removeAttribute("scs_data");
        String signature = httpRequest.getParameter("scs_signature");

        if (StringUtils.isBlank(data) || StringUtils.isBlank(signature)) {
            throw new CertificateStatusException("SCS signature or data missing", SCS_SIGNATURE_FAILED);
        }

        boolean signatureValid = CertificateUtil.checkSignature(data, signature, certificate);
        if (!signatureValid) {
            throw new CertificateStatusException("SCS signature validity check failed", SCS_SIGNATURE_FAILED);
        }
        return certificate;
    }
}
