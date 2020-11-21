package org.keycloak.services.clientpolicy.condition;

import org.jboss.logging.Logger;
import org.keycloak.component.ComponentModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.services.clientpolicy.ClientPolicyContext;
import org.keycloak.services.clientpolicy.ClientPolicyLogger;
import org.keycloak.services.clientpolicy.ClientPolicyVote;

public class ClientDomainNameCondition implements ClientPolicyConditionProvider {
    private static final Logger logger = Logger.getLogger(ClientDomainNameCondition.class);

    private final KeycloakSession session;
    private final ComponentModel componentModel;

    public ClientDomainNameCondition(KeycloakSession session, ComponentModel componentModel) {
        this.session = session;
        this.componentModel = componentModel;
    }

    @Override
    public String getName() {
        return componentModel.getName();
    }

    @Override
    public String getProviderId() {
        return componentModel.getProviderId();
    }

    @Override
    public ClientPolicyVote applyPolicy(ClientPolicyContext context) {
        switch (context.getEvent()) {
            case TOKEN_REQUEST:
            case TOKEN_REFRESH:
            case TOKEN_REVOKE:
            case TOKEN_INTROSPECT:
            case USERINFO_REQUEST:
            case LOGOUT_REQUEST:
                return isClientDomainMatched()
                               ? ClientPolicyVote.YES
                               : ClientPolicyVote.NO;
            default:
                return ClientPolicyVote.ABSTAIN;
        }
    }

    private boolean isClientDomainMatched() {
        String remoteHost = session.getContext().getConnection().getRemoteHost();
        componentModel.getConfig().get(ClientDomainNameConditionFactory.CDN)
                .forEach(d -> log("client domain name expected = " + d));
        log("client domain name expected = " + remoteHost);
        boolean match = componentModel.getConfig().get(ClientDomainNameConditionFactory.CDN).stream()
                                .anyMatch(a -> a.equals(remoteHost));
        log("client domain name" + (match ? "matched." : "unmatched."));
        return match;
    }

    private static void log(String message) {
        ClientPolicyLogger.log(logger, message);
    }
}
