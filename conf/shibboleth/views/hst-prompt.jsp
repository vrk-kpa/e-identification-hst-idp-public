<%@ page contentType="text/html; charset=UTF-8" %>
<%@ page import="net.shibboleth.idp.authn.ExternalAuthentication" %>
<%@ page import="org.opensaml.profile.context.ProfileRequestContext" %>
<%@ page import="fi.vm.kapa.identification.shibboleth.extauthn.authn.AbstractAuthnHandler" %>
<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c" %>

<%
    final ProfileRequestContext prc = ExternalAuthentication.getProfileRequestContext(request.getParameter(ExternalAuthentication.CONVERSATION_KEY), request);
    final String samlRequestLang = AbstractAuthnHandler.resolveLanguage(prc);
%>

<!doctype html>
<!--[if lte IE 7]> <html lang="fi" itemtype="http://schema.org/WebPage" data-text-size="3" class="no-js text-size-3 lte_ie9 lte_ie8 lte7"> <![endif]-->
<!--[if IE 8]> <html lang="fi" itemtype="http://schema.org/WebPage" data-text-size="3" class="no-js text-size-3 lte_ie9 lte_ie8 ie8"> <![endif]-->
<!--[if IE 9]> <html lang="fi" itemtype="http://schema.org/WebPage" data-text-size="3" class="no-js text-size-3 lte_ie9 ie9"> <![endif]-->
<!--[if gt IE 9]><!--><html lang="fi" itemtype="http://schema.org/WebPage" data-text-size="3" class="no-js text-size-3"><!--<![endif]-->
<head>
    <meta charset="utf-8">
    <meta http-equiv="x-ua-compatible" content="ie=edge">
    <title data-i18n="header__suomifi_tunnistaminen">Suomi.fi-tunnistaminen</title>
    <meta name="description" content="">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link rel="stylesheet" href="/resources/stylesheets/style.css">
    <script src="/resources/js/vendor/modernizr-2.8.3.min.js"></script>
    <script src="/resources/js/vendor/jquery-1.11.2.min.js"></script>
    <script src="/resources/js/plugins.js"></script>
    <script src="/resources/js/main.js"></script>
    <script src="/resources/js/vendor/js.cookie.js"></script>
    <script src="/resources/js/vendor/i18next.min.js"></script>
    <script src="/resources/js/vendor/jquery-i18next.js"></script>
    <script src="/resources/js/vendor/i18nextXHRBackend.min.js"></script>
    <script src="/resources/js/vendor/domready.js"></script>
    <script src="/resources/js/idp_localisation.js"></script>
    <script>
        // clear, set lang cookie based on SAML
        Cookies.remove('E-Identification-Lang');
        document.cookie="E-Identification-Lang=<%=samlRequestLang%>;path=/;secure";

        function setLanguage(lang) {
            idpLocalisation.setUserLanguageCookie(lang);
            location.reload();
        }
        domready(function () {
            var language = idpLocalisation.getLanguage();
            $(".language-selection > li > a[lang=" + language + "]").attr("class", "selected");
            idpLocalisation.localise(language, '#identification-service', '/static/localisation',
                    'suomifi-tunnistaminen-resource-08_tunnistus_hst_labels');
        });
    </script>
    <!--[if lt IE 9]>
    <script src="/resources/js/vendor/respond.js"></script>
    <script src="/resources/js/scs/jquery.xdomainrequest.min.js"></script>
    <![endif]-->
    <!--[if IE 8]>
    <link href="/resources/stylesheets/ie8.css" rel="stylesheet" type="text/css" />
    <![endif]-->
    <script src="/resources/js/scs/scs.js"></script>
    <script>
      function scs_init() {
        $.ajax({
          dataType: "json",
          url: "<%= request.getContextPath() %>/scs/initialize",
          success: function(json) {
            scs_auth(json.data,json.issuers);
          },
          error: function() {
            scs_fallback(); // fallback to legacy method
          }
        });
      };

      function scs_auth(data,issuers) {
        var request = {
          selector: {},
          content: data,
          contentType: "data",
          hashAlgorithm: "SHA256",
          signatureType: "signature",
          version: "1.0"
        };
        request.selector.keyusages = [ "digitalsignature" ];
        if (Array.isArray(issuers)) {
          request.selector.issuers = issuers;
        }
        SCS.sign(scs_handle,request);
      };

      function scs_handle(response) {
        if (typeof response === 'object' && response.status === "ok")
        {
          // "status": "ok", "reasonCode": "200", "reasonText": "Signature generated"
          $("#scs_signature").val(response.signature);
          $("#scs_cert").val(response.chain[0]); // SCS specification: user cert always at index 0
          $("#login-form-scs").submit();
        }
        else if (typeof response === 'object' && (response.reasonCode === "400" || response.reasonCode === "401"))
        {
          // "status": "failed", "reasonCode": "400", "reasonText": "Bad request: No acceptable user certificates available."
          // "status": "failed", "reasonCode": "400", "reasonText": "Bad request: Please insert smart card"
          // "status": "failed", "reasonCode": "401", "reasonText": "Unauthorized: Operation cancelled"
          $("#tunnistaudu").prop("disabled", false); // re-enable button
        }
        else // SCS internal error / failure?
        {
          scs_fallback(); // fallback to legacy method
        }
      };

      function scs_fallback() // Init legacy method (called if SCS fails)
      {
        $.get("/certcheck", function() {
          $("#login-form").submit();
        }).fail(function() {
          window.location.replace(window.location.href + "&e=1");
        });
      }
    </script>

</head>
<body id="identification-service" class="txlive">
<a href="#main" class="visuallyhidden focusable">Siirry suoraan sisältöön</a>
<header id="page-header" role="banner">
    <div id="site-options">
        <div class="container">
            <ul class="language-selection">
                <li><a lang="fi" onclick="setLanguage('fi')"><span>Suomeksi</span></a></li>
                <li><a lang="sv" onclick="setLanguage('sv')"><span>På svenska</span></a></li>
                <li><a lang="en" onclick="setLanguage('en')"><span>In English</span></a></li>
            </ul>
            <ul class="adjust-font-size" aria-hidden="true">
                <li><button title="Pienennä tekstikokoa" class="decrease-font-size">A-</button></li>
                <li><button title="Suurenna tekstikokoa" class="increase-font-size">A+</button></li>
            </ul>
        </div>
    </div>
    <div id="header-content" class="container">
        <div class="header-row top-row">
            <div class="container">
                <div class="centered">
                    <div class="logo-row">
                        <h1 class="site-logo">
                            <img data-i18n="[src]header__logo;[alt]header__suomifi-tunnistaminen" title="Suomi.fi-tunnistaminen"/>
                        </h1>
                    </div>
                </div>
            </div>
        </div>
        <div class="header-row" id="main-menu">
            <div class="container">
                <div class="header-actions">
                </div>
            </div>
        </div>
    </div>
</header>
<main id="main" role="main" name="main">
    <div class="main">
        <div class="container">
            <c:if test="${empty param.e}">
                <div class="row">
                    <div class="col-xs-12 service-top">
                        <a title="Peruuta ja palaa tunnistusvälineen valintaan" data-i18n="hst__peruuta" href="#" onclick="javascript:history.back();return false;">Peruuta ja palaa tunnistusvälineen valintaan</a>
                    </div>
                </div>
                <div class="row">
                    <div class="col-xs-12">
                        <ol class="numbered-list hst-directions">
                            <li data-i18n="hst__aseta_kortti">Aseta kortti lukijaan.</li>
                            <li data-i18n="hst__odota_hetki">Odota hetki, kunnes kortin tiedot on luettu.</li>
                            <li data-i18n="hst__napsauta">Napsauta Tunnistaudu -painiketta.</li>
                        </ol>
                        <div class="text">
                            <p data-i18n="hst__ohjelmisto_avautuu">Kortinlukijaohjelmisto avautuu. Varsinainen tunnistus tehdään kortinlukijaohjelmistolla. Anna kortin olla paikallaan lukijassa koko tunnistustapahtuman ajan.</p>
                        </div>
                        <ul class="sign-in-option-list role-selection">
                            <li>
                                <form id="login-form" action="<%= request.getContextPath() %>/authn/External" method="post">
                                    <input type="hidden" name="<%= ExternalAuthentication.CONVERSATION_KEY %>"
                                           value="<c:out value="<%= request.getParameter(ExternalAuthentication.CONVERSATION_KEY) %>" />">
                                </form>
                                <form id="login-form-scs" action="<%= request.getContextPath() %>/authn/SCS" method="post">
                                    <input type="hidden" name="<%= ExternalAuthentication.CONVERSATION_KEY %>"
                                           value="<c:out value="<%= request.getParameter(ExternalAuthentication.CONVERSATION_KEY) %>" />">
                                    <input type="hidden" id="scs_signature" name="scs_signature"/>
                                    <input type="hidden" id="scs_cert" name="scs_cert"/>
                                </form>
                                <button id="tunnistaudu" data-i18n="hst__tunnistaudu">Tunnistaudu</button>
                                <script>
                                    $(document).ready(function(){
                                        $("#tunnistaudu").click(function(){
                                          $(this).prop("disabled", true);
                                          scs_init();
                                        });
                                    });
                                </script>
                            </li>
                        </ul>
                    </div>
                </div>
                <div class="row">
                    <h2 data-i18n="hst__hyva_tietaa">Hyvä tietää</h2>
                    <div class="col-xs-12">
                        <div class="text">
                            <p>
                                <span data-i18n="hst__tunnistautuminen_mahdollista">Tunnistautuminen on mahdollista poliisin myöntämällä sirullisella henkilökortilla, jossa on Väestörekisterikeskuksen kansalaisvarmenne. Varmennekortin lisäksi tarvitset kortinlukijalaitteen ja -ohjelmiston. Lisätietoja varmennekortista löydät Väestörekisterikeskuksen </span>
                                <a data-i18n="[href]hst__fineid_url;hst__fineid">FINeID -sivustolta</a>.
                            </p>
                            <p>
                                <span data-i18n="hst__voit_testata">Voit testata kortin toimivuuden Väestörekisterikeskuksen </span>
                                <a data-i18n="[href]hst__testaa_palvelusta_url;hst__testaa_palvelusta">Testaa varmenteesi -palvelusta</a>.
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

                            <h2 data-i18n="hst__virhe">Virhe</h2>
                            <p data-i18n="hst__epaonnistui">Tunnistautuminen varmennekortilla epäonnistui.</p>
                            <c:choose>
                                <c:when test="${error == '5' || error == '6' || error == '10' || error == '11' || error == '12' || error == '13' }">
                                    <%-- VARTTI_SERVICE_ERROR | INTERNAL_ERROR | CRL_OUTDATED | CRL_MISSING | CRL_SIGNATURE_FAILED | SCS_SIGNATURE_FAILED --%>
                                    <ul>
                                        <li data-i18n="hst__sisainen_virhe">Tunnistautumisessa tapahtui virhe ja tunnistautuminen keskeytyi. Tietosi eivät kuitenkaan ole vaarantuneet, eivätkä ne voi päätyä vahingossa muiden tietoon.</li>
                                        <li data-i18n="hst__palautepyynto">Mikäli ongelma toistuu, lähetä meille siitä palautetta, jotta voimme selvittää ja korjata mahdollisesti toistuvan vian.</li>
                                        <li>
                                            <a data-i18n="hst__palautelinkki" href="/sivut/info/virhepalaute/" target="_blank">Lähetä palautetta lomakkeella.</a>
                                            <span class="sr-only" data-i18n="footer__linkki_avautuu_uuteen_ikkunaan">Linkki avautuu uuteen ikkunaan</span>
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
                                        <a data-i18n="[href]hst__testaa_palvelusta_url;hst__testaa_palvelusta">Testaa varmenteesi -palvelusta</a>.
                                    </p>
                                </c:otherwise>
                            </c:choose>

                            <c:choose>
                                <c:when test="${error == '1'}">
                                    <br><a title="Peruuta ja palaa tunnistusvälineen valintaan" data-i18n="hst__peruuta" href="#" onclick="javascript:history.back();return false;">Peruuta ja palaa tunnistusvälineen valintaan</a>
                                </c:when>
                                <c:otherwise>
                                    <form id="login-error" action="<%= request.getContextPath() %>/authn/Error" method="post">
                                        <input type="hidden" name="<%= ExternalAuthentication.CONVERSATION_KEY %>"
                                               value="<c:out value="<%= request.getParameter(ExternalAuthentication.CONVERSATION_KEY) %>" />">
                                        <input type="hidden" name="e"
                                               value="<c:out value="${error}" />">
                                    </form>
                                    <br><a title="Peruuta ja palaa tunnistusvälineen valintaan" data-i18n="hst__peruuta" href="#" onclick="javascript:$('#login-error').submit();return false;">Peruuta ja palaa tunnistusvälineen valintaan</a>
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
    <div class="container">
        <div class="row">
            <div id="footer-logo">
                <img src="/resources/img/footer-logo2.svg" alt="Väestörekisterikeskus logo">
            </div>
            <p>
                <span data-i18n="footer__tunnistuspalvelusta_vastaa">Kansalaisen tunnistuspalvelusta vastaa </span>
                <a id="kansalaisen_palvelusta_vastaa_url" data-i18n="[href]footer__vrk_url;footer__vaestorekisterikeskus"
                   target="_blank">Väestörekisterikeskus</a>
            </p>
            <ul class="link-list">
                <li><a target="_blank" id="footer__tietoa_tunnistautumisesta" data-i18n="footer__tietoa_tunnistautumisesta" href="/sivut/info/tietoapalvelusta/">Tietoa tunnistautumisesta</a>
                    <span class="sr-only" data-i18n="footer__linkki_avautuu_uuteen_ikkunaan">Linkki avautuu uuteen ikkunaan<span>
                </li>
                <li><a target="_blank" id="footer__palaute" data-i18n="footer__anna_palautetta" href="/sivut/info/palaute/">Anna palautetta</a>
                    <span class="sr-only" data-i18n="footer__linkki_avautuu_uuteen_ikkunaan">Linkki avautuu uuteen ikkunaan<span>
                </li>
                <li><a target="_blank" id="footer__tietosuojaseloste" data-i18n="footer__tietosuojaseloste" href="/sivut/info/tietosuojaseloste/">Henkilötietolain mukainen tietosuojaseloste</a>
                    <span class="sr-only" data-i18n="footer__linkki_avautuu_uuteen_ikkunaan">Linkki avautuu uuteen ikkunaan<span>
                </li>
                <li><a target="_blank" id="footer__virhepalaute" data-i18n="footer__virhepalaute" href="/sivut/info/virhepalaute/">Ilmoita virheestä</a>
                    <span class="sr-only" data-i18n="footer__linkki_avautuu_uuteen_ikkunaan">Linkki avautuu uuteen ikkunaan<span>
                </li>
            </ul>
        </div>
    </div>
</footer>
</body>
</html>
