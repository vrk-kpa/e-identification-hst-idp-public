<%@ page contentType="text/html; charset=UTF-8" %>
<%@ page import="net.shibboleth.idp.authn.ExternalAuthentication" %>
<%@ page import="org.opensaml.profile.context.ProfileRequestContext" %>
<%@ page import="fi.vm.kapa.identification.shibboleth.extauthn.authn.AbstractAuthnHandler" %>
<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c" %>

<%
    final ProfileRequestContext prc = ExternalAuthentication.getProfileRequestContext(request.getParameter(ExternalAuthentication.CONVERSATION_KEY), request);
    final String samlRequestLang = AbstractAuthnHandler.resolveLanguage(prc);
    String cancel = request.getParameter("cancel");
    if (cancel != null) {
        request.setAttribute(ExternalAuthentication.AUTHENTICATION_ERROR_KEY, "User canceled authentication");
        ExternalAuthentication.finishExternalAuthentication(request.getParameter(ExternalAuthentication.CONVERSATION_KEY), request, response);
    }
%>

<!doctype html>
<!--[if lte IE 7]> <html lang="fi" itemtype="http://schema.org/WebPage" class="no-js lte_ie9 lte_ie8 lte7"> <![endif]-->
<!--[if IE 8]> <html lang="fi" itemtype="http://schema.org/WebPage" class="no-js lte_ie9 lte_ie8 ie8"> <![endif]-->
<!--[if IE 9]> <html lang="fi" itemtype="http://schema.org/WebPage" class="no-js lte_ie9 ie9"> <![endif]-->
<!--[if gt IE 9]><!--><html lang="fi" itemtype="http://schema.org/WebPage" class="no-js"><!--<![endif]-->
<head>
    <meta charset="utf-8">
    <meta http-equiv="x-ua-compatible" content="ie=edge">
    <title data-i18n="hst__tunnistaudu_varmennekortilla">Tunnistaudu varmennekortilla</title>
    <meta name="description" content="">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link rel="stylesheet" href="/resources/stylesheets/style.css">
    <script src="/resources/js/vendor/modernizr-2.8.3.min.js"></script>
    <script src="/resources/js/vendor/jquery.min.js"></script>
    <script src="/resources/js/plugins.js"></script>
    <script src="/resources/js/main.js"></script>
    <script src="/resources/js/vendor/js.cookie.js"></script>
    <script src="/resources/js/vendor/i18next.min.js"></script>
    <script src="/resources/js/vendor/jquery-i18next.min.js"></script>
    <script src="/resources/js/vendor/i18nextXHRBackend.min.js"></script>
    <script src="/resources/js/vendor/domready.js"></script>
    <script src="/resources/js/idp_localisation.js"></script>
    <script>
        // clear, set lang cookie based on SAML
        Cookies.remove('E-Identification-Lang');
        document.cookie="E-Identification-Lang=<%=samlRequestLang%>;path=/;secure";

        window.onpopstate = function(event) {
            window.location.href += '&cancel=1';
        };
        history.pushState(null, null);
           
        function setLanguage(lang) {
            idpLocalisation.setUserLanguageCookie(lang);
            location.reload();
        }
        domready(function () {
            var language = idpLocalisation.getLanguage();
            idpLocalisation.localise(language, '#identification-service', '/static/localisation',
                    'suomifi-tunnistaminen-resource-08_tunnistus_hst_labels');
        });
    </script>
    <!--[if lt IE 9]>
    <script src="/resources/js/vendor/respond.js"></script>
    <![endif]-->

</head>
<body id="identification-service" class="txlive">
<a href="#main" class="visuallyhidden focusable">Siirry suoraan sisältöön</a>
<header id="page-header" role="banner">
    <div id="header-content" class="container">
        <h1 id="suomi.fi-tunnistaminen" class="site-logo">
            <img data-i18n="[src]header__logo;[alt]header__suomifi-tunnistaminen" title="Suomi.fi-tunnistus" />
            <span data-i18n="header__suomifi-tunnistaminen" class="visuallyhidden" />
        </h1>
    </div>
</header>
<main id="main" role="main" name="main">
    <div class="main hst-idp-page">
        <div class="container">
            <c:if test="${empty param.e}">
                <h1 data-i18n="hst__tunnistaudu_varmennekortilla">Tunnistaudu varmennekortilla</h1>
                <div class="row">
                    <div class="col-xs-12 col-md-8">
                        <div class="box hst-identification-info">
                            <ol class="numbered-list">
                                <li><span data-i18n="hst__aseta_kortti">Aseta kortti lukijaan.</span><span data-i18n="[title]hst__tunnistautuminen_mahdollista_lyhyt" class="hst-info" /></li>
                                <img src="/resources/img/card.svg" class="hst-image" />
                                <li data-i18n="hst__odota_hetki">Odota hetki, kunnes kortin tiedot on luettu.</li>
                                <li data-i18n="hst__napsauta">Napsauta Tunnistaudu -painiketta.</li>
                            </ol>
                            <div class="row">
                                <form id="login-form" action="<%= request.getContextPath() %>/authn/External" method="post">
                                    <input type="hidden" name="<%= ExternalAuthentication.CONVERSATION_KEY %>"
                                           value="<c:out value="<%= request.getParameter(ExternalAuthentication.CONVERSATION_KEY) %>" />">
                                </form>
                                <button id="tunnistaudu" data-i18n="hst__tunnistaudu">Tunnistaudu</button>
                                <p class="hst-help small" data-i18n="hst__ohjelmisto_avautuu">Kortinlukijaohjelmisto avautuu. Varsinainen tunnistus tehdään kortinlukijaohjelmistolla. Anna kortin olla paikallaan lukijassa koko tunnistustapahtuman ajan.</p>
                                <script>
                                    function disableFooter() {
                                        $(".footer-links").find("a").addClass("disabled-link").removeAttr("href");
                                        $(".sign-in-info").find("a").addClass("disabled-link").removeAttr("href");
                                    }
                                   $(document).ready(function(){
                                        $("#tunnistaudu").click(function(){
                                            disableFooter();
                                            $.get("/certcheck", function() {
                                              $("#login-form").submit();
                                            }).fail(function() {
                                               window.location.replace(window.location.href + "&e=1");
                                            });
                                        });
                                    });
                                </script>
                            </div>
                        </div>
                    </div>
                </div>
                <div class="row">
                  <a class="go-back" title="Peruuta ja palaa tunnistusvälineen valintaan<" data-i18n="hst__peruuta" href="#" onclick="javascript:history.back();return false;">Palaa tunnistusvälineen valintaan</a>
                </div>
                <div class="row">
                    <div class="col-xs-12 col-md-8">
                        <div class="sign-in-info">
                            <p class="small">
                                <span data-i18n="hst__tunnistautuminen_mahdollista">Tunnistautuminen on mahdollista sähköisellä henkilökortilla ja Väestörekisterikeskuksen myöntämällä sosiaali- ja terveydenhuollon ammattikortilla sekä organisaatiokortilla.</span>
                            </p>
                            <p class="small">
                                <span data-i18n="hst__varmennekortin_lisaksi">Varmennekortin lisäksi tarvitset kortinlukijalaitteen ja -ohjelmiston. Kortinlukijaohjelmiston voit ladata maksutta</span>
                                <a data-i18n="[href]hst__kortinlukijaohjelmisto_url;hst__kortinlukijaohjelmisto">Väestörekisterikeskuksen verkkosivuilta.</a>
                            </p>
                            <p class="small">
                                <span data-i18n="hst__voit_testata">Voit testata kortin toimivuuden Väestörekisterikeskuksen</span>
                                <a data-i18n="[href]hst__testaa_palvelussa_url;hst__testaa_palvelussa">Testaa varmenteesi -palvelussa.</a>
                                <span data-i18n="hst__voit_testata_2"></span>
                            </p>
                        </div>
                    </div>
                </div>
            </c:if>

            <c:if test="${not empty param.e}">
                <c:set var="error" scope="session" value="${param.e}" />
                <div class="row">
                    <div class="col-xs-12 col-md-8">
                        <div class="error-box">
                            <h1 data-i18n="hst__virhe">Virhe</h1>
                            <p data-i18n="hst__epaonnistui">Tunnistautuminen varmennekortilla epäonnistui.</p>
                            <c:choose>
                                <c:when test="${error == '5' || error == '6' || error == '10' || error == '11' || error == '12' || error == '13' }">
                                    <%-- VARTTI_SERVICE_ERROR | INTERNAL_ERROR | CRL_OUTDATED | CRL_MISSING | CRL_SIGNATURE_FAILED | SCS_SIGNATURE_FAILED --%>
                                    <ul>
                                        <li data-i18n="hst__sisainen_virhe">Tunnistautumisessa tapahtui virhe ja tunnistautuminen keskeytyi. Tietosi eivät kuitenkaan ole vaarantuneet, eivätkä ne voi päätyä vahingossa muiden tietoon.</li>
                                        <li data-i18n="hst__palautepyynto">Mikäli ongelma toistuu, lähetä meille siitä palautetta, jotta voimme selvittää ja korjata mahdollisesti toistuvan vian.</li>
                                        <li>
                                            <a data-i18n="hst__palautelinkki" href="/sivut/info/virhepalaute/">Lähetä palautetta lomakkeella.</a>
                                        </li>
                                    </ul>
                                </c:when>
                                <c:otherwise>
                                    <c:choose>
                                        <c:when test="${error == '3'}">
                                            <%-- CERT_REVOKED --%>
                                            <p data-i18n="hst__sulkulistalla">Varmennekortti on sulkulistalla</p>
                                        </c:when>
                                        <c:when test="${error == '7'}">
                                            <%-- CERT_EXPIRED --%>
                                            <p data-i18n="hst__on_vanhentunut">Varmennekortti on vanhentunut.</p>
                                        </c:when>
                                        <c:when test="${error == '4' || error == '8' || error == '9'}">
                                            <%-- CERT_TYPE_NOT_SUPPORTED | UNKNOWN_CA | UNKNOWN_ICA --%>
                                            <p data-i18n="hst__tarkista_tyyppi">Tarkista, että käytössäsi on kansalaisvarmennekortti.</p>
                                        </c:when>
                                        <c:otherwise>
                                            <%-- Fails to read certificate card | NO_CERT_FOUND | Any other error case --%>
                                            <ul>
                                                <li data-i18n="hst__tarkista">Tarkista, että tietokoneeseen on asennettu kortinlukijaohjelmisto.</li>
                                                <li data-i18n="hst__oikein_pain">Tarkista, että kortti on oikein päin lukijalaitteessa.</li>
                                                <li data-i18n="hst__laitteen_toiminta">Tarkista lukijalaitteen toiminta.</li>
                                                <li data-i18n="hst__vanhentunut">Tarkista, että kortti ei ole vanhentunut.</li>
                                            </ul>
                                        </c:otherwise>
                                    </c:choose>
                                    <p>
                                        <span data-i18n="hst__voit_testata">Voit testata kortin toimivuuden Väestörekisterikeskuksen </span>
                                        <a data-i18n="[href]hst__testaa_palvelussa_url;hst__testaa_palvelussa">Testaa varmenteesi -palvelussa</a>
                                    </p>
                                </c:otherwise>
                            </c:choose>

                            <c:choose>
                                <c:when test="${error == '1'}">
                                    <br><a class="go-back" title="Peruuta ja palaa tunnistusvälineen valintaan" data-i18n="hst__peruuta" href="#" onclick="javascript:history.back();return false;">Peruuta ja palaa tunnistusvälineen valintaan</a>
                                </c:when>
                                <c:otherwise>
                                    <form id="login-error" action="<%= request.getContextPath() %>/authn/Error" method="post">
                                        <input type="hidden" name="<%= ExternalAuthentication.CONVERSATION_KEY %>"
                                               value="<c:out value="<%= request.getParameter(ExternalAuthentication.CONVERSATION_KEY) %>" />">
                                        <input type="hidden" name="e"
                                               value="<c:out value="${error}" />">
                                    </form>
                                    <br><a class="go-back" title="Peruuta ja palaa tunnistusvälineen valintaan" data-i18n="hst__peruuta" href="#" onclick="javascript:$('#login-error').submit();return false;">Peruuta ja palaa tunnistusvälineen valintaan</a>
                                </c:otherwise>
                            </c:choose>
                        </div>
                    </div>
                </div>
            </c:if>
        </div>
    </div>
</main>
<footer id="page-footer" role="contentinfo">
    <a href="#" class="go-up" data-i18n="footer__takaisin_ylös">Takaisin ylös</a>
    <div id="footer-content" class="container">
        <span class="site-logo">
            <img data-i18n="[src]header__logo;[alt]header__suomifi-tunnistaminen" alt="Suomi.fi-tunnistus">
        </span>
        <div class="footer-links">
          <ul class="footer-links-info">
              <li><a id="footer__tietoa_tunnistautumisesta" data-i18n="footer__tietoa_tunnistautumisesta" href="/sivut/info/tietoapalvelusta/">Tietoa Suomi.fi-tunnistuksesta</a></li>
              <li><a id="footer__tietosuojaseloste" data-i18n="footer__tietosuojaseloste" href="/sivut/info/tietosuojaseloste/">Tietosuojaseloste</a></li>
          </ul>
          <ul class="footer-links-feedback">
              <li><a id="footer__anna_palautetta" data-i18n="footer__anna_palautetta" href="/sivut/info/palaute/">Anna palautetta</a></li>
              <li><a id="footer__virhepalaute" data-i18n="footer__virhepalaute" href="/sivut/info/virhepalaute/">Ilmoita virheestä</a></li>
          </ul>
        </div>
    </div>
</footer>
</body>
</html>
