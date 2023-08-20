package com.example.security;

import com.example.service.JwtService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.http.HttpHeaders;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
@Slf4j
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {
    public static final String BEARER = "Bearer ";

    private final JwtService jwtService;

    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response, @NonNull FilterChain filterChain)
            throws ServletException, IOException {
        final String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);

        if (missingAuthenticationHeader(authHeader) || missingBearerFromHeader(authHeader)) {
            filterChain.doFilter(request, response);
            return;
        }

        final String jwtToken = StringUtils.substringAfter(authHeader, BEARER);

        if (jwtService.isValidToken(jwtToken) && authenticationNotAvailableInContext()) {
            SecurityContext context = SecurityContextHolder.createEmptyContext();
            UsernamePasswordAuthenticationToken authToken =
                    jwtService.createAuthentication(jwtToken);
            authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
            context.setAuthentication(authToken);
            SecurityContextHolder.setContext(context);
        }
        filterChain.doFilter(request, response);
    }

    private static boolean authenticationNotAvailableInContext() {
        return SecurityContextHolder.getContext().getAuthentication() == null;
    }

    private static boolean missingAuthenticationHeader(String authHeader) {
        return StringUtils.isBlank(authHeader);
    }

    private static boolean missingBearerFromHeader(String authHeader) {
        return !StringUtils.startsWith(authHeader, BEARER);
    }
}