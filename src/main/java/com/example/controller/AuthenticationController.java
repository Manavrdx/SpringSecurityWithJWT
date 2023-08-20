package com.example.controller;

import com.example.entity.Session;
import com.example.security.dto.*;
import com.example.security.event.InvalidTokenEvent;
import com.example.service.AuthenticationService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.collections4.CollectionUtils;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@Slf4j
@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthenticationController {
    private final AuthenticationService authenticationService;
    private final ApplicationEventPublisher applicationEventPublisher;

    @PostMapping("/signup")
    public ResponseEntity<JwtAuthenticationResponse> signup(
            @RequestBody @Valid SignUpRequest request) {
        return ResponseEntity.ok(authenticationService.signup(request));
    }

    @PostMapping("/signin")
    public ResponseEntity<JwtAuthenticationResponse> signin(
            @RequestBody @Valid SigninRequest request) {
        JwtAuthenticationResponse jwtAuthenticationResponse = authenticationService.signin(request);

        triggerLogoutEvent(jwtAuthenticationResponse);
        return ResponseEntity.ok(jwtAuthenticationResponse);
    }

    @PostMapping("/signin-exclusively")
    public ResponseEntity<JwtAuthenticationResponse> signInExclusively(
            @RequestBody @Valid SigninRequest request) {
        JwtAuthenticationResponse jwtAuthenticationResponse =
                authenticationService.signinExclusively(request);
        triggerLogoutEvent(jwtAuthenticationResponse);
        return ResponseEntity.ok(jwtAuthenticationResponse);
    }

    @PostMapping("/refresh")
    public ResponseEntity<JwtAuthenticationResponse> refresh(
            @RequestBody @Valid RefreshTokenRequest refreshTokenRequest) {
        return ResponseEntity.ok(authenticationService.refresh(refreshTokenRequest));
    }

    @PostMapping("/logout")
    public ResponseEntity<String> logoutUser(@Valid @RequestBody LogOutRequest logOutRequest) {
        String userName = authenticationService.logout(logOutRequest);
        InvalidTokenEvent logoutSuccessEvent = new InvalidTokenEvent(userName, logOutRequest);
        applicationEventPublisher.publishEvent(logoutSuccessEvent);

        return ResponseEntity.ok("User has successfully logged out from the system!");
    }

    // ====================Private Methods====================================================
    private void triggerLogoutEvent(JwtAuthenticationResponse jwtAuthenticationResponse) {
        List<Session> loggedOutSessions = jwtAuthenticationResponse.getLoggedOutSessions();
        if (CollectionUtils.isEmpty(loggedOutSessions)) {
            return;
        }

        loggedOutSessions.forEach(userSessionDetail -> {
            try {
                InvalidTokenEvent logoutSuccessEvent = new InvalidTokenEvent(
                    jwtAuthenticationResponse.getUserName(),
                    new LogOutRequest(userSessionDetail.getActiveAccessToken(), userSessionDetail.getActiveRefreshToken())
                );
                logoutSuccessEvent.setMetaData("Event During SignIn");
                applicationEventPublisher.publishEvent(logoutSuccessEvent);
            } catch (Exception exception) {
                log.error("Exception In Capturing Logout Event:: ", exception);
            }
        });
    }
}