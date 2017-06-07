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

package fi.vm.kapa.identification.shibboleth.extauthn.scs;

import fi.vm.kapa.identification.shibboleth.extauthn.exception.SCSException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import com.fasterxml.jackson.databind.ObjectMapper;

@WebServlet(name = "SCSInitializerServlet", urlPatterns = {"/scs/initialize"})
public class SCSInitializerServlet extends HttpServlet {

    private static final Logger logger = LoggerFactory.getLogger(SCSInitializerServlet.class);

    @Override
    public void service(final HttpServletRequest httpRequest, final HttpServletResponse httpResponse)
            throws ServletException, IOException {

        try {
            // Generate 64 bytes of secure random data (for signature verification)
            String data = SCSInitializer.generateData(64);

            // Store generated random data to session
            HttpSession session = httpRequest.getSession(true);
            session.setAttribute("scs_data", data);

            // Generate SCSInitResponse object
            SCSInitResponse scsInitResponse = new SCSInitResponse();
            scsInitResponse.setData(data);

            // Convert to JSON
            String response = new ObjectMapper().writeValueAsString(scsInitResponse);

            httpResponse.setCharacterEncoding("UTF-8");
            httpResponse.setStatus(HttpServletResponse.SC_OK);
            httpResponse.setContentType("application/json");
            httpResponse.getWriter().write(response);

        }
        catch (SCSException e) { // SCS disabled
            httpResponse.setStatus(HttpServletResponse.SC_SERVICE_UNAVAILABLE);
        }
        catch (Exception e) {
            logger.error("SCSInitializerServlet got exception: "+e.getMessage(), e);
            httpResponse.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
        }
        httpResponse.getWriter().flush();
        httpResponse.getWriter().close();

    }
}