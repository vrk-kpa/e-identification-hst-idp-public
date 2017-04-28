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
package fi.vm.kapa.identification.shibboleth.extauthn.vartti;

import javax.ws.rs.client.Client;
import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.client.Invocation;
import javax.ws.rs.client.WebTarget;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import fi.vm.kapa.identification.shibboleth.extauthn.exception.VarttiServiceException;
import fi.vm.kapa.identification.vartticlient.model.VarttiResponse;
import org.glassfish.jersey.client.ClientConfig;
import org.glassfish.jersey.jackson.JacksonFeature;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;

@Component
public class VarttiClient {

    private final String varttiClientEndpoint;

    private static final Logger logger = LoggerFactory.getLogger(VarttiClient.class);

    public VarttiClient(String varttiClientEndpoint) {
        this.varttiClientEndpoint = varttiClientEndpoint;
    }

    public String getHetu(String serial, String issuerCN, String certSerial) throws VarttiServiceException {

        Response response = getVarttiHttpResponse(serial, issuerCN, certSerial);

        int status = response.getStatus();
        if ( status == HttpStatus.OK.value()) {
            VarttiResponse varttiResponse = getValidVarttiResponse(response);
            return varttiResponse.getVarttiPerson().getHetu();
        } else {
            logger.warn("Vartti connection failed with status code " + status);
            throw new VarttiServiceException("Vartti connection failed with status code " + status);
        }
    }

    Response getVarttiHttpResponse(String serial, String issuerCN, String certSerial) throws VarttiServiceException {
        try {
            WebTarget webTarget = getClient()
                    .target(varttiClientEndpoint)
                    .path(serial)
                    .path(certSerial)
                    .queryParam("issuerCN", issuerCN);

            Invocation.Builder invocationBuilder = webTarget.request(MediaType.APPLICATION_JSON);
            return invocationBuilder.get();
        } catch (Exception e) {
            logger.error("Vartti client connection not established. Service request failed.", e);
            throw new VarttiServiceException("Vartti client connection not established. Service request failed.");
        }
    }

    VarttiResponse getValidVarttiResponse(Response response) throws VarttiServiceException {
        VarttiResponse varttiResponse = response.readEntity(VarttiResponse.class);
        if ( varttiResponse == null ) {
            logger.error("Vartti client response was null.");
            throw new VarttiServiceException("Vartti client response was null.");
        }
        else if ( varttiResponse.isSuccess() ) {
            return varttiResponse;
        }
        else if ( varttiResponse.getError() != null ) {
            String msg = "Vartti client response failed: " + varttiResponse.getError();
            logger.warn(msg);
            throw new VarttiServiceException(msg);
        }
        else {
            logger.warn("Vartti client response failed.");
            throw new VarttiServiceException("Vartti client response failed.");
        }
    }

    private Client getClient() {
        ClientConfig clientConfig = new ClientConfig();
        Client client = ClientBuilder.newClient(clientConfig);
        client.register(JacksonFeature.class);
        return client;
    }

}
