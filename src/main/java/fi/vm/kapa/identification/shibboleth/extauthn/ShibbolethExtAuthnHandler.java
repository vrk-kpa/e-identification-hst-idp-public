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

import fi.vm.kapa.identification.shibboleth.extauthn.context.HSTCardContext;
import fi.vm.kapa.identification.shibboleth.extauthn.context.OrganizationCardContext;
import fi.vm.kapa.identification.shibboleth.extauthn.exception.CertificateStatusException;
import fi.vm.kapa.identification.shibboleth.extauthn.exception.VarttiServiceException;
import fi.vm.kapa.identification.shibboleth.extauthn.vartti.VarttiClient;
import static fi.vm.kapa.identification.shibboleth.extauthn.exception.CertificateStatusException.ErrorCode.*;
import net.shibboleth.idp.authn.AuthnEventIds;
import net.shibboleth.idp.authn.ExternalAuthentication;
import net.shibboleth.idp.authn.ExternalAuthenticationException;

import net.shibboleth.idp.authn.context.AuthenticationContext;
import org.apache.commons.lang.StringUtils;
import org.cryptacular.x509.dn.NameReader;
import org.cryptacular.x509.dn.RDNSequence;
import org.cryptacular.x509.dn.StandardAttributeType;
import org.opensaml.profile.context.ProfileRequestContext;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.core.Extensions;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.beans.factory.config.AutowireCapableBeanFactory;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.context.support.WebApplicationContextUtils;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Set;

@WebServlet(name = "ShibbolethExtAuthnHandler", urlPatterns = {"/authn/External/*"})
public class ShibbolethExtAuthnHandler extends HttpServlet {
     
    private static final Logger log = LoggerFactory.getLogger(ShibbolethExtAuthnHandler.class);

    @Autowired
    private transient VarttiClient varttiClient;

    @Autowired
    private transient CertificateUtil certificateUtil;

    @Value("${hst.prompt.url}")
    private String hstPromptUrl;

    @Value("${oc.ca.orgname.set}")
    private String allowedCNOfOrganizationCardCA;

    @Override
    public void init(ServletConfig config) throws ServletException {
        WebApplicationContext springContext = WebApplicationContextUtils.getRequiredWebApplicationContext(config.getServletContext());
        final AutowireCapableBeanFactory beanFactory = springContext.getAutowireCapableBeanFactory();
        beanFactory.autowireBean(this);
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
                    log.debug("--" + header + " <--> " + httpRequest.getHeader(header));
                }

                try {
                    final X509Certificate cert = certificateUtil.getValidCertificate(httpRequest);

                    log.debug("End-entity X.509 certificate found with subject '{}', issued by '{}'",
                            cert.getSubjectDN().getName(), cert.getIssuerDN().getName());

                    final RDNSequence dn = new NameReader(cert).readSubject();
                    final String subjectSerialNumber = dn.getValue(StandardAttributeType.SerialNumber);

                    // set sub context and finish external authentication
                    setIDCardSubContext(httpRequest, key, cert, subjectSerialNumber);
                    httpRequest.setAttribute(ExternalAuthentication.PRINCIPAL_NAME_KEY, subjectSerialNumber);
                    ExternalAuthentication.finishExternalAuthentication(key, httpRequest, httpResponse);

                } catch ( CertificateStatusException ste ) {
                    httpResponse.sendRedirect(createErrorURL(key, ste.getErrorCode()));
                }
            } else {
                //Return to discovery page call from error page
                final String error = httpRequest.getParameter("e");
                final String key = httpRequest.getParameter("conversation");
                if (error.equals(NO_CERT_FOUND.getCode()) && StringUtils.isNotBlank(key)) {
                    httpRequest.setAttribute(ExternalAuthentication.AUTHENTICATION_ERROR_KEY,
                            AuthnEventIds.NO_CREDENTIALS);
                    ExternalAuthentication.finishExternalAuthentication(key, httpRequest, httpResponse);
                } else if ( error.equals(CERT_REVOKED.getCode()) && StringUtils.isNotBlank(key)) {
                    httpRequest.setAttribute(ExternalAuthentication.AUTHENTICATION_ERROR_KEY,
                            AuthnEventIds.INVALID_CREDENTIALS);
                    ExternalAuthentication.finishExternalAuthentication(key, httpRequest, httpResponse);
                } else {
                    //Unknown error
                    httpRequest.setAttribute(ExternalAuthentication.AUTHENTICATION_ERROR_KEY,
                            AuthnEventIds.AUTHN_EXCEPTION);
                    ExternalAuthentication.finishExternalAuthentication(key, httpRequest, httpResponse);
                }

            }
        } catch (final ExternalAuthenticationException e) {
            log.error("Error processing external authentication request");
            throw new ServletException("Error processing external authentication request", e);
        }
    }

    private String createErrorURL(String key, CertificateStatusException.ErrorCode errorID) {
        return hstPromptUrl + "?conversation=" + key + "&e=" + errorID.getCode();
    }

    private void setIDCardSubContext(HttpServletRequest httpRequest, String key, X509Certificate cert, String subjectSerialNumber) throws IOException, ExternalAuthenticationException, CertificateStatusException {

        AuthenticationContext ac = ExternalAuthentication.getProfileRequestContext(key, httpRequest).getSubcontext(AuthenticationContext.class);
        if ( ac == null ) {
            log.warn("Authentication context not valid");
            throw new CertificateStatusException("Authentication context not valid", INTERNAL_ERROR);
        }

        final String issuerCommonName = new NameReader(cert).readIssuer().getValue(StandardAttributeType.CommonName);

        if ( isOrganizationCardType(issuerCommonName) ) {
            // get hetu from vartti
            try {
                OrganizationCardContext occ = new OrganizationCardContext(varttiClient.getHetu(subjectSerialNumber, issuerCommonName, String.valueOf(cert.getSerialNumber())));
                ac.addSubcontext(occ);
            } catch (VarttiServiceException vse) {
                log.warn("Getting hetu from vartti client failed", vse);
                throw new CertificateStatusException("Getting hetu from vartti client failed", VARTTI_SERVICE_ERROR);
            }
        }
        else {
            // satu
            HSTCardContext hcc = new HSTCardContext(subjectSerialNumber, issuerCommonName);
            ac.addSubcontext(hcc);
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
                    .filter(extension -> "kapa".equals(extension.getElementQName().getLocalPart()))
                    .findFirst()
                    .flatMap(kapaNode -> kapaNode.getOrderedChildren()
                            .stream()
                            .filter(lgNode -> "lang".equals(lgNode.getElementQName().getLocalPart()))
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

    private boolean isOrganizationCardType(String issuerCN) {
        Set<String> allowedCommonNames = new HashSet<>(Arrays.asList(allowedCNOfOrganizationCardCA.split(";")));
        for ( String allowedName : allowedCommonNames ) {
            if ( issuerCN.equals(allowedName) ) {
                return true;
            }
        }
        return false;
    }

}