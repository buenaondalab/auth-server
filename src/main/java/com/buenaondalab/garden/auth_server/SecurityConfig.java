package com.buenaondalab.garden.auth_server;

import java.util.List;
import java.util.Set;
import java.util.logging.Logger;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.client.ServiceInstance;
import org.springframework.cloud.client.discovery.DiscoveryClient;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.web.client.ResourceAccessException;

@Configuration
@Profile("security")
public class SecurityConfig {

    private static final Logger log = Logger.getLogger(SecurityConfig.class.getName());

    @Bean
    RegisteredClientRepository oauth2ClientRepository(DiscoveryClient dc,
        @Value("${garden.oauth2.client-id}") String clientId,
        @Value("${garden.oauth2.client-secret}") String clientSecret) {
        RegisteredClient client =
            RegisteredClient.withId(clientId)
                .clientId(clientId)
                .clientName("Garden Gateway Oauth2 Client")
                .clientSecret(clientSecret)
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .redirectUris(uris -> getUris(uris, dc, clientId)) //TODO check
                .scopes(scopes -> scopes.addAll(Set.of(OidcScopes.OPENID, OidcScopes.PROFILE))) //TODO add scopes
                .clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build())
                .build();
        return new InMemoryRegisteredClientRepository(client);
    }

    // TODO: if docker-compose is well configured, retry is not needed. gateway depends on auth-server
    private void getUris(Set<String> uris, DiscoveryClient dc, String registrationId) {
            try {
                List<ServiceInstance> instances = dc.getInstances(registrationId);
                if(instances.size() > 0) {
                    instances.forEach(s -> {
                        final String uri = s.getUri() + "/login/oauth2/code/" + registrationId;
                        uris.add(uri);
                        log.info("OAuth2 redirect-uri " + uri + " ADDED for " + registrationId + " client");
                    });
                    //TODO: HealthCheck positive...
                } else {
                    log.warning(() -> "No " + registrationId + " instances available. Impossible to calculate OAuth2 redirect-uri");
                    uris.add("http://localhost:8080/login/oauth2/code/gateway");
                //TODO: HealthCheck negative...

                }
            } catch (ResourceAccessException ce) {
                log.warning(() -> "Unable to retrieve " + registrationId + " OAuth2 client configuration\n" + ce.getMessage());
                uris.add("http://localhost:8080/login/oauth2/code/gateway");
                //TODO: HealthCheck negative...
            }
        }
}
