package org.keycloak.services.clientpolicy.condition;

import org.keycloak.Config;
import org.keycloak.component.ComponentModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.ArrayList;
import java.util.List;

public class ClientDomainNameConditionFactory implements ClientPolicyConditionProviderFactory {
    public static final String PROVIDER_ID = "client-domain-name-condition";
    public static final String CDN = "domname";

    private static final List<ProviderConfigProperty> configProperties = new ArrayList<>();

    static {
        ProviderConfigProperty property;
        property = new ProviderConfigProperty(CDN, PROVIDER_ID + ".label", PROVIDER_ID + ".tooltip", ProviderConfigProperty.MULTIVALUED_STRING_TYPE, "http://localhost:8080");
        configProperties.add(property);
    }

    @Override
    public ClientPolicyConditionProvider create(KeycloakSession session, ComponentModel model) {
        return new ClientDomainNameCondition(session, model);
    }

    @Override
    public void init(Config.Scope config) {
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
    }

    @Override
    public void close() {
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getHelpText() {
        return "It uses the client's domain name to determine whether the policy is applied.";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return configProperties;
    }
}
