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

import net.shibboleth.idp.authn.AuthnEventIds;
import net.shibboleth.idp.authn.ExternalAuthentication;
import net.shibboleth.idp.authn.ExternalAuthenticationException;
import org.apache.commons.lang.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

import static fi.vm.kapa.identification.shibboleth.extauthn.exception.CertificateStatusException.ErrorCode.CERT_REVOKED;
import static fi.vm.kapa.identification.shibboleth.extauthn.exception.CertificateStatusException.ErrorCode.CERT_TYPE_NOT_SUPPORTED;
import static fi.vm.kapa.identification.shibboleth.extauthn.exception.CertificateStatusException.ErrorCode.NO_CERT_FOUND;


@WebServlet(name = "ShibbolethExtAuthnHandlerError", urlPatterns = {"/authn/Error/*"})
public class ShibbolethExtAuthnHandlerError extends HttpServlet {

    private static final Logger log = LoggerFactory.getLogger(ShibbolethExtAuthnHandlerError.class);

    @Override
    public void service(final HttpServletRequest httpRequest, final HttpServletResponse httpResponse)
            throws ServletException, IOException {
        try {
            final String key = httpRequest.getParameter("conversation");
            if ( StringUtils.isNotBlank(key) ) {
                //Return to discovery page call from error page
                final String error = httpRequest.getParameter("e");
                if (NO_CERT_FOUND.getCode().equals(error)) {
                    httpRequest.setAttribute(ExternalAuthentication.AUTHENTICATION_ERROR_KEY, AuthnEventIds.NO_CREDENTIALS);
                } else if (CERT_REVOKED.getCode().equals(error) || CERT_TYPE_NOT_SUPPORTED.getCode().equals(error))  {
                    httpRequest.setAttribute(ExternalAuthentication.AUTHENTICATION_ERROR_KEY, AuthnEventIds.INVALID_CREDENTIALS);
                } else {
                    //Unknown error
                    httpRequest.setAttribute(ExternalAuthentication.AUTHENTICATION_ERROR_KEY, AuthnEventIds.AUTHN_EXCEPTION);
                }
                ExternalAuthentication.finishExternalAuthentication(key, httpRequest, httpResponse);
            }
        } catch (final ExternalAuthenticationException e) {
            log.error("Error processing external authentication request");
            throw new ServletException("Error processing external authentication request", e);
        }
    }

}