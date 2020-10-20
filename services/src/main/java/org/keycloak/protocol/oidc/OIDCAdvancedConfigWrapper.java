/*
 * Copyright 2016 Red Hat, Inc. and/or its affiliates
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

package org.keycloak.protocol.oidc;

import org.keycloak.authentication.authenticators.client.X509ClientAuthenticator;
import org.keycloak.jose.jws.Algorithm;
import org.keycloak.models.ClientModel;
import org.keycloak.representations.idm.ClientRepresentation;

import java.util.HashMap;

/**
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class OIDCAdvancedConfigWrapper {

    private final ClientModel clientModel;
    private final ClientRepresentation clientRep;

    private OIDCAdvancedConfigWrapper(ClientModel client, ClientRepresentation clientRep) {
        this.clientModel = client;
        this.clientRep = clientRep;
    }


    public static OIDCAdvancedConfigWrapper fromClientModel(ClientModel client) {
        return new OIDCAdvancedConfigWrapper(client, null);
    }

    public static OIDCAdvancedConfigWrapper fromClientRepresentation(ClientRepresentation clientRep) {
        return new OIDCAdvancedConfigWrapper(null, clientRep);
    }


    public Algorithm getUserInfoSignedResponseAlg() {
        String alg = getAttribute(OIDCConfigAttributes.USER_INFO_RESPONSE_SIGNATURE_ALG);
        return alg==null ? null : Enum.valueOf(Algorithm.class, alg);
    }

    public void setUserInfoSignedResponseAlg(Algorithm alg) {
        String algStr = alg==null ? null : alg.toString();
        setAttribute(OIDCConfigAttributes.USER_INFO_RESPONSE_SIGNATURE_ALG, algStr);
    }

    public boolean isUserInfoSignatureRequired() {
        return getUserInfoSignedResponseAlg() != null;
    }

    public Algorithm getRequestObjectSignatureAlg() {
        String alg = getAttribute(OIDCConfigAttributes.REQUEST_OBJECT_SIGNATURE_ALG);
        return alg==null ? null : Enum.valueOf(Algorithm.class, alg);
    }

    public void setRequestObjectSignatureAlg(Algorithm alg) {
        String algStr = alg==null ? null : alg.toString();
        setAttribute(OIDCConfigAttributes.REQUEST_OBJECT_SIGNATURE_ALG, algStr);
    }
    
    public String getRequestObjectRequired() {
        return getAttribute(OIDCConfigAttributes.REQUEST_OBJECT_REQUIRED);
    }
    
    public void setRequestObjectRequired(String requestObjectRequired) {
        setAttribute(OIDCConfigAttributes.REQUEST_OBJECT_REQUIRED, requestObjectRequired);
    }

    public boolean isUseJwksUrl() {
        String useJwksUrl = getAttribute(OIDCConfigAttributes.USE_JWKS_URL);
        return Boolean.parseBoolean(useJwksUrl);
    }

    public void setUseJwksUrl(boolean useJwksUrl) {
        String val = String.valueOf(useJwksUrl);
        setAttribute(OIDCConfigAttributes.USE_JWKS_URL, val);
    }

    public String getJwksUrl() {
        return getAttribute(OIDCConfigAttributes.JWKS_URL);
    }

    public void setJwksUrl(String jwksUrl) {
        setAttribute(OIDCConfigAttributes.JWKS_URL, jwksUrl);
    }

    public boolean isExcludeSessionStateFromAuthResponse() {
        String excludeSessionStateFromAuthResponse = getAttribute(OIDCConfigAttributes.EXCLUDE_SESSION_STATE_FROM_AUTH_RESPONSE);
        return Boolean.parseBoolean(excludeSessionStateFromAuthResponse);
    }

    public void setExcludeSessionStateFromAuthResponse(boolean excludeSessionStateFromAuthResponse) {
        String val = String.valueOf(excludeSessionStateFromAuthResponse);
        setAttribute(OIDCConfigAttributes.EXCLUDE_SESSION_STATE_FROM_AUTH_RESPONSE, val);
    }

    // KEYCLOAK-6771 Certificate Bound Token
    // https://tools.ietf.org/html/draft-ietf-oauth-mtls-08#section-6.5
    public boolean isUseMtlsHokToken() {
        String useUtlsHokToken = getAttribute(OIDCConfigAttributes.USE_MTLS_HOK_TOKEN);
        return Boolean.parseBoolean(useUtlsHokToken);
    }

    public void setUseMtlsHoKToken(boolean useUtlsHokToken) {
        String val = String.valueOf(useUtlsHokToken);
        setAttribute(OIDCConfigAttributes.USE_MTLS_HOK_TOKEN, val);
    }

    public String getTlsClientAuthSubjectDn() {
        return getAttribute(X509ClientAuthenticator.ATTR_SUBJECT_DN);
     }

    public void setTlsClientAuthSubjectDn(String tls_client_auth_subject_dn) {
        setAttribute(X509ClientAuthenticator.ATTR_SUBJECT_DN, tls_client_auth_subject_dn);
    }

    public String getPkceCodeChallengeMethod() {
        return getAttribute(OIDCConfigAttributes.PKCE_CODE_CHALLENGE_METHOD);
    }

    public void setPkceCodeChallengeMethod(String codeChallengeMethodName) {
        setAttribute(OIDCConfigAttributes.PKCE_CODE_CHALLENGE_METHOD, codeChallengeMethodName);
    }

    public String getIdTokenSignedResponseAlg() {
        return getAttribute(OIDCConfigAttributes.ID_TOKEN_SIGNED_RESPONSE_ALG);
    }
    public void setIdTokenSignedResponseAlg(String algName) {
        setAttribute(OIDCConfigAttributes.ID_TOKEN_SIGNED_RESPONSE_ALG, algName);
    }

    public String getIdTokenEncryptedResponseAlg() {
        return getAttribute(OIDCConfigAttributes.ID_TOKEN_ENCRYPTED_RESPONSE_ALG);
    }

    public void setIdTokenEncryptedResponseAlg(String algName) {
        setAttribute(OIDCConfigAttributes.ID_TOKEN_ENCRYPTED_RESPONSE_ALG, algName);
    }

    public String getIdTokenEncryptedResponseEnc() {
        return getAttribute(OIDCConfigAttributes.ID_TOKEN_ENCRYPTED_RESPONSE_ENC);
    }

    public void setIdTokenEncryptedResponseEnc(String encName) {
        setAttribute(OIDCConfigAttributes.ID_TOKEN_ENCRYPTED_RESPONSE_ENC, encName);
    }

    public String getTokenEndpointAuthSigningAlg() {
        return getAttribute(OIDCConfigAttributes.TOKEN_ENDPOINT_AUTH_SIGNING_ALG);
    }

    public void setTokenEndpointAuthSigningAlg(String algName) {
        setAttribute(OIDCConfigAttributes.TOKEN_ENDPOINT_AUTH_SIGNING_ALG, algName);
    }

    public String getBackchannelLogoutUrl() {
        return getAttribute(OIDCConfigAttributes.BACKCHANNEL_LOGOUT_URL);
    }

    public void setBackchannelLogoutUrl(String backchannelLogoutUrl) {
        setAttribute(OIDCConfigAttributes.BACKCHANNEL_LOGOUT_URL, backchannelLogoutUrl);
    }

    public boolean isBackchannelLogoutSessionRequired() {
        String backchannelLogoutSessionRequired = getAttribute(OIDCConfigAttributes.BACKCHANNEL_LOGOUT_SESSION_REQUIRED);
        return Boolean.parseBoolean(backchannelLogoutSessionRequired);
    }

    public void setBackchannelLogoutSessionRequired(boolean backchannelLogoutSessionRequired) {
        String val = String.valueOf(backchannelLogoutSessionRequired);
        setAttribute(OIDCConfigAttributes.BACKCHANNEL_LOGOUT_SESSION_REQUIRED, val);
    }

    public boolean getBackchannelLogoutRevokeOfflineTokens() {
        String backchannelLogoutRevokeOfflineTokens = getAttribute(OIDCConfigAttributes.BACKCHANNEL_LOGOUT_REVOKE_OFFLINE_TOKENS);
        return Boolean.parseBoolean(backchannelLogoutRevokeOfflineTokens);
    }

    public void setBackchannelLogoutRevokeOfflineTokens(boolean backchannelLogoutRevokeOfflineTokens) {
        String val = String.valueOf(backchannelLogoutRevokeOfflineTokens);
        setAttribute(OIDCConfigAttributes.BACKCHANNEL_LOGOUT_REVOKE_OFFLINE_TOKENS, val);
    }

    public String getBackchannelTokenDeliveryMode() {
        return getAttribute(OIDCConfigAttributes.BACKCHANNEL_TOKEN_DELIVERY_MODE);
    }

    public void setBackchannelTokenDeliveryMode(String backchannelTokenDeliveryMode) {
        setAttribute(OIDCConfigAttributes.BACKCHANNEL_TOKEN_DELIVERY_MODE, backchannelTokenDeliveryMode);
    }

    private String getAttribute(String attrKey) {
        if (clientModel != null) {
            return clientModel.getAttribute(attrKey);
        } else {
            return clientRep.getAttributes()==null ? null : clientRep.getAttributes().get(attrKey);
        }
    }

    private void setAttribute(String attrKey, String attrValue) {
        if (clientModel != null) {
            if (attrValue != null) {
                clientModel.setAttribute(attrKey, attrValue);
            } else {
                clientModel.removeAttribute(attrKey);
            }
        } else {
            if (attrValue != null) {
                if (clientRep.getAttributes() == null) {
                    clientRep.setAttributes(new HashMap<>());
                }
                clientRep.getAttributes().put(attrKey, attrValue);
            } else {
                if (clientRep.getAttributes() != null) {
                    clientRep.getAttributes().put(attrKey, null);
                }
            }
        }
    }

    public boolean getLoginHintEncodingEnabledParameter() {
        String loginHintEncodingEnabled = getAttribute(OIDCConfigAttributes.CIBA_LOGIN_HINT_ENCODING_ENABLED);
        return Boolean.parseBoolean(loginHintEncodingEnabled);
    }

    public void setLoginHintEncodingEnabledParameter(boolean loginHintEncodingEnabled) {
        String val = String.valueOf(loginHintEncodingEnabled);
        setAttribute(OIDCConfigAttributes.CIBA_LOGIN_HINT_ENCODING_ENABLED, val);
    }
}
