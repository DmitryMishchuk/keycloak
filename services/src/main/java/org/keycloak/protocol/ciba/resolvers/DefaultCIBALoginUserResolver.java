package org.keycloak.protocol.ciba.resolvers;

import org.apache.commons.lang.StringUtils;
import org.jboss.logging.Logger;
import org.keycloak.crypto.Aes128GcmEncryptor;
import org.keycloak.crypto.CibaLoginHintEncryptor;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.protocol.ciba.decoupledauthn.DelegateDecoupledAuthenticationProvider;
import org.keycloak.protocol.oidc.OIDCConfigAttributes;

import java.security.GeneralSecurityException;

public class DefaultCIBALoginUserResolver implements CIBALoginUserResolver {

    private KeycloakSession session;
    private static final Logger logger = Logger.getLogger(DelegateDecoupledAuthenticationProvider.class);

    public DefaultCIBALoginUserResolver(KeycloakSession session) {
        this.session = session;
    }

    @Override
    public UserModel getUserFromLoginHint(String loginHint) {
        String secret = session.getContext().getClient().getSecret();
        if (session.getContext().getClient().getAttributes().get(OIDCConfigAttributes.CIBA_LOGIN_HINT_ENCODING_ENABLED)!=null && secret != null && !secret.isEmpty()) {
            try {
                loginHint = CibaLoginHintEncryptor.decodeLoginHint(secret,loginHint);
            } catch (GeneralSecurityException e) {
                logger.error(e.getMessage());
                throw new RuntimeException("Unable to get user by login_hint. \nError: " + e.getMessage());
            }
        }
        return KeycloakModelUtils.findUserByNameOrEmail(session, session.getContext().getRealm(), loginHint);
    }

    @Override
    public UserModel getUserFromLoginHintToken(String loginHintToken) {
        // not yet supported
        return null;
    }

    @Override
    public UserModel getUserFromIdTokenHint(String idToken) {
        // not yet supported
        return null;
    }

    @Override
    public String getInfoUsedByAuthentication(UserModel user) {
        return user.getUsername();
    }

    @Override
    public UserModel getUserFromInfoUsedByAuthentication(String info) {
        return KeycloakModelUtils.findUserByNameOrEmail(session, session.getContext().getRealm(), info);
    }

    @Override
    public void close() {
    }

}
