package com.hermesworld.ais.galapagos.security;

import com.github.tomakehurst.wiremock.junit5.WireMockExtension;
import com.github.tomakehurst.wiremock.junit5.WireMockRuntimeInfo;
import com.hermesworld.ais.galapagos.applications.ApplicationsService;
import com.hermesworld.ais.galapagos.applications.controller.ApplicationsController;
import com.hermesworld.ais.galapagos.kafka.KafkaClusters;
import com.hermesworld.ais.galapagos.security.config.GalapagosSecurityProperties;
import com.hermesworld.ais.galapagos.staging.StagingService;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.*;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;

import java.net.URI;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Map;
import java.util.Objects;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.wireMockConfig;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

@SpringBootTest(classes = { SecurityConfig.class, ApplicationsController.class,
        GalapagosSecurityProperties.class }, webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@EnableAutoConfiguration
class SecurityConfigIntegrationTest {

    @LocalServerPort
    private int port;

    @Autowired
    private TestRestTemplate restTemplate;

    @SuppressWarnings("unused")
    @MockBean
    private ApplicationsService applicationsService;

    @SuppressWarnings("unused")
    @MockBean
    private StagingService stagingService;

    @SuppressWarnings("unused")
    @MockBean
    private KafkaClusters kafkaClusters;

    @MockBean
    private JwtDecoder jwtDecoder;

    @RegisterExtension
    static WireMockExtension wm = WireMockExtension.newInstance()
            .options(wireMockConfig().dynamicPort().globalTemplating(true)).build();

    @BeforeAll
    static void initWireMock() {
        WireMockRuntimeInfo info = wm.getRuntimeInfo();
        System.setProperty("spring.security.oauth2.client.provider.keycloak.issuer-uri",
                "http://localhost:" + info.getHttpPort() + "/auth");

        wm.stubFor(get("/auth/.well-known/openid-configuration").willReturn(
                aResponse().withStatus(200).withHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
                        .withBodyFile("oauth2/openid-configuration.json")));
    }

    @BeforeEach
    void initJwtStuff() {
        when(jwtDecoder.decode(any())).thenAnswer(inv -> {
            String token = inv.getArgument(0);
            Map<String, Object> headers = Map.of("alg", "HS256", "typ", "JWT");
            Map<String, Object> claims = Map.of("sub", "abc123", "iat", "123", "my_roles", token.replace(".", " "));
            return new Jwt(token, Instant.now(), Instant.now().plus(1, ChronoUnit.DAYS), headers, claims);
        });
    }

    @Test
    void test_apiAccessProtected() {
        var factory = restTemplate.getRestTemplate().getRequestFactory();
        System.out.println(factory);
        ResponseEntity<String> response = restTemplate.getForEntity("http://localhost:" + port + "/api/me/requests",
                String.class);
        // must redirect to Spring's "login" page
        assertEquals(HttpStatus.FOUND.value(), response.getStatusCode().value());
        assertTrue(Objects.requireNonNull(response.getHeaders().getFirst(HttpHeaders.LOCATION))
                .endsWith("/oauth2/authorization/keycloak"));
    }

    @Test
    void test_apiAccess_missingUserRole() {
        testApiWithRole("/api/me/requests", "NOT_A_USER", HttpStatus.FORBIDDEN.value());
    }

    @Test
    void test_apiAccess_withUserRole() {
        testApiWithRole("/api/me/requests", "USER", HttpStatus.OK.value());
    }

    @Test
    void test_apiAccess_adminEndpoint_withUserRole() {
        testApiWithRole("/api/admin/requests", "USER", HttpStatus.FORBIDDEN.value());
    }

    @Test
    void test_apiAccess_adminEndpoint_withAdminRole() {
        testApiWithRole("/api/admin/requests", "USER.ADMIN", HttpStatus.OK.value());
    }

    private void testApiWithRole(String endpoint, String roleName, int expectedCode) {
        String url = "http://localhost:" + port + endpoint;

        HttpHeaders headers = new HttpHeaders();
        headers.add(HttpHeaders.AUTHORIZATION, "Bearer " + roleName);

        HttpEntity<String> request = new RequestEntity<>(headers, HttpMethod.GET, URI.create(url));
        ResponseEntity<String> response = restTemplate.exchange(url, HttpMethod.GET, request, String.class);
        assertEquals(expectedCode, response.getStatusCode().value());
    }

}
