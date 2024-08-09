package com.hermesworld.ais.galapagos.security.impl;

import com.hermesworld.ais.galapagos.events.EventContextSource;
import com.hermesworld.ais.galapagos.security.AuditPrincipal;
import com.hermesworld.ais.galapagos.security.CurrentUserService;
import com.hermesworld.ais.galapagos.security.config.GalapagosSecurityProperties;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

@Component
public class DefaultCurrentUserService implements CurrentUserService, EventContextSource {

    private final GalapagosSecurityProperties securityConfig;

    public DefaultCurrentUserService(GalapagosSecurityProperties securityConfig) {
        this.securityConfig = securityConfig;
    }

    @Override
    public Optional<String> getCurrentUserName() {
        SecurityContext context = SecurityContextHolder.getContext();
        if (context.getAuthentication() == null || context.getAuthentication().getPrincipal() == null
                || !context.getAuthentication().isAuthenticated()
                || context.getAuthentication() instanceof AnonymousAuthenticationToken) {
            return Optional.empty();
        }

        return Optional.of(context.getAuthentication().getName());
    }

    @Override
    public Optional<AuditPrincipal> getCurrentPrincipal() {
        return getCurrentUserName().map(name -> new AuditPrincipal(name, getCurrentUserDisplayName().orElse(null)));
    }

    @Override
    public Optional<String> getCurrentUserEmailAddress() {
        return extractClaimFromAuthentication(securityConfig.getJwtEmailClaim());
    }

    @Override
    public Optional<String> getCurrentUserDisplayName() {
        return extractClaimFromAuthentication(securityConfig.getJwtDisplayNameClaim());
    }

    private Optional<String> extractClaimFromAuthentication(String claim) {
        SecurityContext context = SecurityContextHolder.getContext();
        Authentication auth = context.getAuthentication();
        if (auth instanceof JwtAuthenticationToken token) {
            return Optional.ofNullable(token.getToken().getClaimAsString(claim));
        }
        if (auth instanceof OAuth2AuthenticationToken oauth2) {
            return Optional.ofNullable(oauth2.getPrincipal().getAttribute(claim));
        }

        return Optional.empty();
    }

    @Override
    public Map<String, Object> getContextValues() {
        Map<String, Object> result = new HashMap<>();
        result.put("username", getCurrentUserName().orElse(null));
        result.put("email", getCurrentUserEmailAddress().orElse(null));
        result.put("principal", getCurrentPrincipal().orElse(null));
        return result;
    }

    @Override
    public boolean isAdmin() {
        SecurityContext context = SecurityContextHolder.getContext();
        if (context.getAuthentication() == null || context.getAuthentication().getAuthorities() == null) {
            return false;
        }
        return context.getAuthentication().getAuthorities().stream()
                .anyMatch(auth -> auth.getAuthority().equals("ROLE_ADMIN"));
    }

}
