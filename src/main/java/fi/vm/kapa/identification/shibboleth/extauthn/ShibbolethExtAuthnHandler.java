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
import org.cryptacular.x509.dn.NameReader;
import org.cryptacular.x509.dn.RDNSequence;
import org.cryptacular.x509.dn.StandardAttributeType;
import org.opensaml.profile.context.ProfileRequestContext;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.core.Extensions;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Properties;
import java.util.Set;

@WebServlet(name = "ShibbolethExtAuthnHandler", urlPatterns = {"/authn/External/*"})
public class ShibbolethExtAuthnHandler extends HttpServlet {

    public static final String NO_CERT_FOUND = "2";
    public static final String CERT_REVOKED_OR_NOT_VALID = "3";
    public static final String CERT_TYPE_NOT_SUPPORTED = "4";
     
    private final static Logger log = LoggerFactory.getLogger(ShibbolethExtAuthnHandler.class);

    private String icaPath;
    private String caPath;
    private String crlPath;
    private String crlUpdateTimeValidation;
    private String SATU_DELIMITER;
    private String hstPromptUrl;
    private String allowedOUNamesOfCA;

    public void init(ServletConfig config) throws ServletException {
        try {
            Properties props = new Properties();
            props.load(new FileInputStream("/opt/identity-provider/hst-identity-provider.properties"));
            this.icaPath = props.getProperty("ica.dir.path");
            this.caPath = props.getProperty("ca.dir.path");
            this.crlPath = props.getProperty("crl.dir.path");
            this.SATU_DELIMITER = props.getProperty("satu.issuer.delimiter");
            this.crlUpdateTimeValidation = props.getProperty("crl.updatetime.validation");
            this.hstPromptUrl = props.getProperty("hst.prompt.url");
            this.allowedOUNamesOfCA = props.getProperty("ca.orgname.set");
        }
        catch (Exception e) {
            log.error("Error initializing ShibbolethExtAuthnHandler", e);
        }
    }

    @Override
    public void service(final HttpServletRequest httpRequest, final HttpServletResponse httpResponse)
            throws ServletException, IOException {
        try {
            //Check error parameter
            if (StringUtils.isBlank(httpRequest.getParameter("e"))) {
                final String key = ExternalAuthentication.startExternalAuthentication(httpRequest);

                // Debug logs
                Enumeration<String> headers = httpRequest.getHeaderNames();
                while (headers.hasMoreElements()) {
                    String header = headers.nextElement();
                    String headerValue = httpRequest.getHeader(header);
                    log.debug("--" + header + " <--> " + headerValue);
                }

                //Extract client certificate from request
                final X509Certificate cert = CertificateUtil.getCertFromHeader(httpRequest.getHeader("SSL_CLIENT_CERT"));
                if (cert == null || !httpRequest.getHeader("SSL_CLIENT_VERIFY").equalsIgnoreCase("SUCCESS")) {
                    log.warn("No valid X.509 certificates found in request");
                    httpResponse.sendRedirect(hstPromptUrl + "?conversation=" + key + "&e=" + NO_CERT_FOUND);
                    return;
                }
                log.debug("End-entity X.509 certificate found with subject '{}', issued by '{}'",
                        cert.getSubjectDN().getName(), cert.getIssuerDN().getName());

                //Check certificate validity
                final RDNSequence dn = new NameReader(cert).readSubject();
                final String satu = dn.getValue(StandardAttributeType.SerialNumber);
                CertificateUtil crlUtil = new CertificateUtil(cert, icaPath, caPath, crlPath, crlUpdateTimeValidation);
              
                if (isCATypeValid(cert.getIssuerDN().getName()) == false) {
                    log.warn("Certificate type not supported: "+ cert.getIssuerDN().getName());
                    httpResponse.sendRedirect(hstPromptUrl + "?conversation=" + key + "&e=" + CERT_TYPE_NOT_SUPPORTED);
                    return;
                }
                
                if (crlUtil.checkCertificateStatus() == false) {
                    log.warn("X.509 certificate validity check failed");
                    httpResponse.sendRedirect(hstPromptUrl + "?conversation=" + key + "&e=" + CERT_REVOKED_OR_NOT_VALID);
                    return;
                }
                
                final String issuerStr = new NameReader(cert).readIssuer().getValue(StandardAttributeType.CommonName);
                String satuAndIssuerDn = satu + SATU_DELIMITER + issuerStr;
                httpRequest.setAttribute(ExternalAuthentication.PRINCIPAL_NAME_KEY, satuAndIssuerDn);
                ExternalAuthentication.finishExternalAuthentication(key, httpRequest, httpResponse);
            } else {
                //Return to discovery page call from error page
                final String error = httpRequest.getParameter("e");
                final String key = httpRequest.getParameter("conversation");
                if (error.equals(NO_CERT_FOUND) && StringUtils.isNotBlank(key)) {
                    httpRequest.setAttribute(ExternalAuthentication.AUTHENTICATION_ERROR_KEY,
                            AuthnEventIds.NO_CREDENTIALS);
                    ExternalAuthentication.finishExternalAuthentication(key, httpRequest, httpResponse);
                } else {
                    if ( (error.equals(CERT_REVOKED_OR_NOT_VALID) || error.equals(CERT_TYPE_NOT_SUPPORTED)) && StringUtils.isNotBlank(key)) {
                        httpRequest.setAttribute(ExternalAuthentication.AUTHENTICATION_ERROR_KEY,
                                AuthnEventIds.INVALID_CREDENTIALS);
                        ExternalAuthentication.finishExternalAuthentication(key, httpRequest, httpResponse);
                        return;
                    } else {
                        //Unknown error
                        httpRequest.setAttribute(ExternalAuthentication.AUTHENTICATION_ERROR_KEY,
                                AuthnEventIds.AUTHN_EXCEPTION);
                        ExternalAuthentication.finishExternalAuthentication(key, httpRequest, httpResponse);
                        return;
                    }
                }
            }
        } catch (final ExternalAuthenticationException e) {
            log.error("Error processing external authentication request");
            throw new ServletException("Error processing external authentication request", e);
        }
    }

    /**
     * Resolves language from a specific SAML extension.
     *
     * @param prc
     * @return language code
     */
    public static String resolveLanguage(ProfileRequestContext prc) {
        AuthnRequest message = (AuthnRequest) prc.getInboundMessageContext().getMessage();
        Extensions extensions = message.getExtensions();
        String defaultLang = "fi";
        if (extensions != null) {
            // look for vetuma-style language parameter for backward compatibility
            String lang = extensions.getOrderedChildren()
                    .stream()
                    .filter(extension -> extension.getElementQName().getLocalPart().equals("kapa"))
                    .findFirst()
                    .flatMap(kapaNode -> kapaNode.getOrderedChildren()
                            .stream()
                            .filter(lgNode -> lgNode.getElementQName().getLocalPart().equals("lang"))
                            .findFirst())
                    .map(langNode -> langNode.getDOM().getFirstChild().getNodeValue())
                    .orElse(defaultLang);
            log.debug("Resolved language parameter from authentication request - " + lang);
            return lang;
        }
        else {
            log.debug("Could not find language parameter in authentication request, using default language - " + defaultLang);
            return defaultLang;
        }
    }

    private boolean isCATypeValid(String iCAName) {
        String ouPrefix = "OU=";
        Set<String> iCATypes = new HashSet<>(Arrays.asList(allowedOUNamesOfCA.split(";")));
        Set<String> iCANameParts = new HashSet<>(Arrays.asList(iCAName.split(", ")));
        for (String ouValue : iCANameParts) {
            if (ouValue.startsWith(ouPrefix)) {
                ouValue = ouValue.substring(ouPrefix.length());
                if (iCATypes.contains(ouValue)) {
                    return true;
                }
            }
        }
        return false;
    }
}