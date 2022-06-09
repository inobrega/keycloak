/*
 * Copyright 2022 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.keycloak.testsuite.services.clientpolicy.executor;

import java.security.PublicKey;

import org.jboss.logging.Logger;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.protocol.oidc.mappers.HardcodedClaim;
import org.keycloak.protocol.oidc.mappers.OIDCAttributeMapperHelper;
import org.keycloak.representations.idm.ClientPolicyExecutorConfigurationRepresentation;
import org.keycloak.services.clientpolicy.ClientPolicyContext;
import org.keycloak.services.clientpolicy.ClientPolicyEvent;
import org.keycloak.services.clientpolicy.ClientPolicyException;
import org.keycloak.services.clientpolicy.context.TokenResponseContext;
import org.keycloak.services.clientpolicy.executor.ClientPolicyExecutorProvider;

/**
 * @author <a href="mailto:takashi.norimatsu.ws@hitachi.com">Takashi Norimatsu</a>
 */
public class TestDPoPSimulateExecutor implements ClientPolicyExecutorProvider<ClientPolicyExecutorConfigurationRepresentation> {

    public static final String DUMMY_JKT = "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I";

    private static final Logger logger = Logger.getLogger(TestDPoPSimulateExecutor.class);

    protected final KeycloakSession session;

    private PublicKey DPoPPublicKey;

    public TestDPoPSimulateExecutor(KeycloakSession session) {
        this.session = session;
    }

    @Override
    public String getProviderId() {
        return TestDPoPSimulateExecutorFactory.PROVIDER_ID;
    }

    @Override
    public void executeOnEvent(ClientPolicyContext context) throws ClientPolicyException {
        ClientPolicyEvent event = context.getEvent();
        logger.tracev("Client Policy Trigger Event = {0}",  event);
        switch (event) {
            case TOKEN_RESPONSE:
                verifyDPoPProof(context);
                bindTokensWithDPoPPublicKey((TokenResponseContext)context);
                break;
            case TOKEN_REFRESH_RESPONSE:
                verifyDPoPProof(context);
                verifyBindingTokensWithDPoPPublicKey((TokenResponseContext)context);
                bindTokensWithDPoPPublicKey((TokenResponseContext)context);
                break;
            default :
                return;
        }
    }

    private void verifyDPoPProof(ClientPolicyContext context) throws ClientPolicyException {
        // retrieve a DPoP Proof JWT from the "DPoP" HTTP header
        //String DPoPProofJwtString = session.getContext().getRequestHeaders().getHeaderString("DPoP");

        // retrieve a DPoP public key from the DPoP Proof JWT

        // verify a signature of DPoP Proof JWT with the DPoP public key
        // if it fails, raise ClientPolicyException
        //throw new ClientPolicyException("invalid_dpop_proof", "verifying a signature of DPoP Proof JWT with the DPoP public key failed.");
    }

    private void bindTokensWithDPoPPublicKey(TokenResponseContext context) {
        // calculate "jkt" against the DPoP public key
        String jkt = DUMMY_JKT;
        // set cnf.jkt to an access token and a refresh token
        ProtocolMapperModel mappingModel = HardcodedClaim.create("hard", "cnf.jkt", jkt, "String", true, true);
        OIDCAttributeMapperHelper.mapClaim(context.getAccessTokenResponseBuilder().getAccessToken(), mappingModel, jkt);
        OIDCAttributeMapperHelper.mapClaim(context.getAccessTokenResponseBuilder().getRefreshToken(), mappingModel, jkt);
    }

    private void verifyBindingTokensWithDPoPPublicKey(TokenResponseContext context) {
        // retrieve a DPoP public key from the DPoP Proof JWT
        // verify the DPoP public key's digest is equal to cnf.jkt of an access token
        // verify the DPoP public key's digest is equal to cnf.jkt of an refresh token
        // if it fails, raise ClientPolicyException
        //throw new ClientPolicyException("invalid_dpop_proof", "verifying binding a token with DPoP public key failed.");
    }
}