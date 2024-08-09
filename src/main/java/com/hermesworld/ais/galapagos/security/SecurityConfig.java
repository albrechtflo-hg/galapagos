package com.hermesworld.ais.galapagos.security;

import com.hermesworld.ais.galapagos.security.config.GalapagosSecurityProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.core.convert.converter.Converter;
import org.springframework.http.HttpHeaders;
import org.springframework.lang.NonNull;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.core.session.SessionRegistryImpl;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.user.OidcUserAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.session.RegisterSessionAuthenticationStrategy;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.util.matcher.AndRequestMatcher;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import java.util.Collection;
import java.util.HashSet;
import java.util.Locale;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Galapagos Endpoint Security Configuration. Configures, roughly, the following rules:
 * <ul>
 * <li>Calls to <code>/api/**</code> MAY authenticate using a JWT token from the configured OAuth2 provider. Token must
 * contain a valid claim that the user has the USER role.</li>
 * <li>Calls to <code>/app/**</code>, <code>/api/**</code> (if not carrying a JWT token as Bearer token),
 * <code>/assets/**</code> MUST be authenticated using OAuth2 login.</li>
 * <li>Calls to <code>/login/**</code>, <code>/oauth2/**</code>, and <code>/logout</code> are freely accessible (for
 * Spring login and callback mechanism).</li>
 * </ul>
 * The Galapagos Security Configuration is used to extract roles and user info from the JWT token or OAuth2 login
 * information. Role names are converted to upper case.
 */
@Configuration
@EnableMethodSecurity(securedEnabled = true, prePostEnabled = false)
public class SecurityConfig {

    @Bean
    @Order(1)
    SecurityFilterChain apiFilterChain(HttpSecurity http, GalapagosSecurityProperties config) throws Exception {
        RequestMatcher matcher = new AndRequestMatcher(new AntPathRequestMatcher("/api/**"),
                bearerTokenRequestMatcher());
        http.csrf(csrf -> csrf.disable());
        http.securityMatchers(conf -> conf.requestMatchers(matcher));
        http.authorizeHttpRequests(reg -> reg.anyRequest().hasRole("USER"));
        http.oauth2ResourceServer(conf -> conf.jwt(jwtCustomizer(config)));
        http.sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
        return http.build();
    }

    @Bean
    @Order(2)
    SecurityFilterChain uiFilterChain(HttpSecurity http, GalapagosSecurityProperties config) throws Exception {
        // the UI Filter chain ALSO includes /api/** to enable XHR requests from the frontend using only the JSESSIONID
        // cookie
        http.securityMatcher("/api/**", "/app/**", "/assets/**", "/login/**", "/oauth2/**", "/logout");

        // @formatter:off
        http.authorizeHttpRequests(reg -> reg.requestMatchers("/api/me").permitAll()
                .requestMatchers("/api/**", "/app/**", "/assets/**").hasRole("USER")
                .requestMatchers("/login/**", "/oauth2/**", "/logout").permitAll());
        // @formatter:on
        http.oauth2Login(loginConfig -> loginConfig
                .userInfoEndpoint(userInfo -> userInfo.userAuthoritiesMapper(userAuthoritiesMapper(config))));
        http.csrf(csrf -> csrf.ignoringRequestMatchers("/logout"));
        http.logout(Customizer.withDefaults());

        HttpSessionRequestCache requestCache = new HttpSessionRequestCache();

        // disable ?continue= request param
        requestCache.setMatchingRequestParameterName(null);
        http.requestCache(cache -> cache.requestCache(requestCache));

        return http.build();
    }

    @Bean
    public SessionAuthenticationStrategy sessionAuthenticationStrategy() {
        return new RegisterSessionAuthenticationStrategy(new SessionRegistryImpl());
    }

    private GrantedAuthoritiesMapper userAuthoritiesMapper(GalapagosSecurityProperties config) {
        return (authorities) -> {
            Set<GrantedAuthority> mappedAuthorities = new HashSet<>();

            authorities.forEach(authority -> {
                if (authority instanceof OidcUserAuthority oidcUserAuthority) {
                    OidcIdToken idToken = oidcUserAuthority.getIdToken();
                    mappedAuthorities.addAll(extractGrantedAuthorities(idToken, config.getJwtRoleClaim()));
                }
            });

            return mappedAuthorities;
        };
    }

    private RequestMatcher bearerTokenRequestMatcher() {
        return request -> {
            String actualHeaderValue = request.getHeader(HttpHeaders.AUTHORIZATION);
            return actualHeaderValue != null && actualHeaderValue.startsWith("Bearer ");
        };
    }

    private Customizer<OAuth2ResourceServerConfigurer<HttpSecurity>.JwtConfigurer> jwtCustomizer(
            GalapagosSecurityProperties config) {
        return jwtConfigurer -> jwtConfigurer.jwtAuthenticationConverter(jwtAuthenticationConverter(config));
    }

    private JwtAuthenticationConverter jwtAuthenticationConverter(GalapagosSecurityProperties config) {
        JwtAuthenticationConverter converter = new JwtAuthenticationConverter();

        converter.setPrincipalClaimName(config.getJwtUserNameClaim());

        JwtGrantedAuthoritiesConverter authoritiesConverter = new JwtGrantedAuthoritiesConverter();
        authoritiesConverter.setAuthoritiesClaimName(config.getJwtRoleClaim());
        authoritiesConverter.setAuthorityPrefix("ROLE_");
        converter.setJwtGrantedAuthoritiesConverter(new UpperCaseJwtGrantedAuthoritiesConverter(authoritiesConverter));

        return converter;
    }

    private Collection<? extends GrantedAuthority> extractGrantedAuthorities(OidcIdToken idToken, String roleClaim) {
        if (!idToken.hasClaim(roleClaim)) {
            return Set.of();
        }
        return idToken.getClaimAsStringList(roleClaim).stream()
                .map(s -> new SimpleGrantedAuthority("ROLE_" + s.toUpperCase(Locale.US))).toList();
    }

    private record UpperCaseJwtGrantedAuthoritiesConverter(JwtGrantedAuthoritiesConverter delegate)
            implements Converter<Jwt, Collection<GrantedAuthority>> {

        @Override
        public Collection<GrantedAuthority> convert(@NonNull Jwt source) {
            return mapToUpperCase(delegate.convert(source));
        }

        private Collection<GrantedAuthority> mapToUpperCase(Collection<GrantedAuthority> authorities) {
            return authorities.stream().map(a -> new SimpleGrantedAuthority(a.getAuthority().toUpperCase(Locale.US)))
                    .collect(Collectors.toSet());
        }
    }

}
