package com.example.service;

import com.example.entity.User;
import com.example.entity.Session;
import com.example.enums.Role;
import com.example.enums.TokenType;
import com.example.repository.UserRepository;
import com.example.repository.UserSessionDetailRepository;
import com.example.security.dto.*;
import com.example.security.exception.JwtSecurityException;
import com.example.security.helper.SessionCreationHelper;
import com.github.f4b6a3.ulid.Ulid;
import com.github.f4b6a3.ulid.UlidCreator;
import lombok.RequiredArgsConstructor;
import org.apache.commons.collections4.CollectionUtils;
import org.apache.commons.lang3.BooleanUtils;
import org.apache.commons.lang3.StringUtils;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.*;

import static com.example.security.exception.JwtSecurityException.JWTErrorCode.REFRESH_TOKEN_ONLY_ALLOWED_WITH_EXPIRED_TOKEN;

@Service
@Transactional(readOnly = true)
@RequiredArgsConstructor
public class AuthenticationService {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;
    private final UserSessionDetailRepository userSessionDetailRepository;
    private final SessionCreationHelper sessionCreationHelper;

    @Transactional
    public JwtAuthenticationResponse signup(SignUpRequest signUpRequest) {
        User user = User.builder()
                .firstName(signUpRequest.getFirstName())
                .lastName(signUpRequest.getLastName())
                .email(signUpRequest.getEmail())
                .password(passwordEncoder.encode(signUpRequest.getPassword()))
                .role(Role.USER)
                .build();
        userRepository.save(user);

        var tokenMappedByType = jwtService.generateBothToken(new UserDetailsImpl(user));

        saveLoginSession(tokenMappedByType, user);

        return JwtAuthenticationResponse.builder()
                .accessToken(tokenMappedByType.get(TokenType.ACCESS_TOKEN))
                .refreshToken(tokenMappedByType.get(TokenType.REFRESH_TOKEN))
                .build();
    }

    private void saveLoginSession(Map<TokenType, String> tokenMappedByType, User user) {
        String accessToken = tokenMappedByType.get(TokenType.ACCESS_TOKEN);
        String refreshToken = tokenMappedByType.get(TokenType.REFRESH_TOKEN);

        Date refreshTokenWillExpireAt = new Date(Ulid.from(refreshToken).getTime());

        Session sessionDetail = new Session();

        sessionDetail.setActiveRefreshToken(refreshToken);
        sessionDetail.setUser(user);
        sessionDetail.setRefreshTokenExpiryDate(refreshTokenWillExpireAt);
        sessionDetail.setActiveAccessToken(accessToken);

        Date date = new Date();
        sessionDetail.setCreatedDate(date);
        sessionDetail.setLastModifiedDate(date);

        userSessionDetailRepository.save(sessionDetail);
    }

    @Transactional
    public JwtAuthenticationResponse signin(SigninRequest request) {
        authenticationManager.authenticate(
            new UsernamePasswordAuthenticationToken(request.getUserName(), request.getPassword())
        );

        User user = loadUserForSignIn(request);
        List<Session> logoutSessions = validateAndReturnLogoutSession(user);

        var tokenMappedByType = jwtService.generateBothToken(new UserDetailsImpl(user));
        saveLoginSession(tokenMappedByType, user);

        return JwtAuthenticationResponse.builder()
                .accessToken(tokenMappedByType.get(TokenType.ACCESS_TOKEN))
                .refreshToken(tokenMappedByType.get(TokenType.REFRESH_TOKEN))
                .loggedOutSessions(logoutSessions)
                .userName(request.getUserName())
                .build();
    }

    private User loadUserForSignIn(SigninRequest request) {
        return userRepository
                .findByEmail(request.getUserName())
                .orElseThrow(
                    () -> new JwtSecurityException(
                            JwtSecurityException.JWTErrorCode.USER_NOT_FOUND,
                            "Invalid email or password"
                    )
                );
    }

    private List<Session> validateAndReturnLogoutSession(User user) {
        List<Session> sessions = user.getSessions();
        if (CollectionUtils.isEmpty(sessions)) return List.of();

        int numberOfSessionsInDB = sessions.size();

        // methods calling order matters here
        removeInActiveSessionFromDB(sessions);
        throwExceptionIfSessionNotAllowed(numberOfSessionsInDB);
        return removeSessionIfAllowed(numberOfSessionsInDB, sessions);
    }

    private List<Session> removeSessionIfAllowed(
            int numberOfSessionsInDB, List<Session> sessions) {
        Integer allowedSessionCount = sessionCreationHelper.getAllowedSessionCount();
        if (sessionCreationHelper.doWeNeedToRemoveOldSession(numberOfSessionsInDB)) {
            sessions.sort(Comparator.comparing(Session::getCreatedDate));

            int sessionListSizeShouldBeForCreatingNewOne = allowedSessionCount - 1;

            List<Session> deletableSessions = new ArrayList<>();
            while (sessions.size() != sessionListSizeShouldBeForCreatingNewOne) {
                deletableSessions.add(sessions.remove(0));
            }
            userSessionDetailRepository.deleteAll(deletableSessions);
            return deletableSessions;
        }
        return List.of();
    }

    private void throwExceptionIfSessionNotAllowed(int numberOfSessionsInDB) {
        if (BooleanUtils.isNotTrue(sessionCreationHelper.canCreateNewSession(numberOfSessionsInDB))) {
            throw new JwtSecurityException(
                JwtSecurityException.JWTErrorCode.MAX_SESSION_REACHED,
                "Session Not Allowed, You Have To Logout From Other Device First"
            );
        }
    }

    private void removeInActiveSessionFromDB(List<Session> sessions) {
        // Collect InActive Sessions Which We Can't Refresh Anymore
        // And Their AccessToken Is Expired And Remove Them From Session List
        // So that we don't count them in user's sessions
        List<Session> inActiveUserSessions = sessions.stream()
                .filter(Session::refreshDateCrossed)
                .filter(this::isAccessTokenExpired)
                .toList();

        if (CollectionUtils.isEmpty(inActiveUserSessions)) {
            return;
        }

        // Delete InActive Sessions From Database
        userSessionDetailRepository.deleteAll(inActiveUserSessions);

        // Remove From Session List
        sessions.removeAll(inActiveUserSessions);
    }

    private boolean isAccessTokenExpired(Session session) {
        String accessToken = session.getActiveAccessToken();
        Date tokenExpiryDate = jwtService.getTokenExpiryFromExpiredJWT(accessToken);
        return tokenExpiryDate.before(new Date());
    }

    @Transactional
    public JwtAuthenticationResponse refresh(RefreshTokenRequest refreshTokenRequest) {
        String accessToken = refreshTokenRequest.getAccessToken();
        throwExceptionIfAccessTokenIsNotExpired(accessToken);

        String refreshToken = refreshTokenRequest.getRefreshToken();
        validateRefreshTokenAsULID(refreshToken);

        String userName = jwtService.getUserNameFromExpiredJWT(accessToken);
        User user = userRepository.findByEmail(userName).orElseThrow(
            () -> new JwtSecurityException(
                    JwtSecurityException.JWTErrorCode.USER_NOT_FOUND,
                    "User Not Found"
            )
        );

        List<Session> sessions = user.getSessions();

        Optional<Session> optionalUserSessionDetail = findInOldSessions(
                sessions, accessToken, refreshToken
        );

        if (optionalUserSessionDetail.isEmpty()) {
            throw new JwtSecurityException(
                JwtSecurityException.JWTErrorCode.SESSION_NOT_FOUND,
                "User Session For Refresh Not Found With Given Tokens"
            );
        }

        Session sessionToUpdate = optionalUserSessionDetail.get();
        Date refreshTokenExpiryDate = sessionToUpdate.getRefreshTokenExpiryDate();

        if (refreshTokenExpiryDate.before(new Date())) {
            throw new JwtSecurityException(
                JwtSecurityException.JWTErrorCode.REFRESH_TOKEN_EXPIRED,
                "Refresh Token Is Expired, Create New Login Request"
            );
        }

        String newAccessToken = jwtService.generateAccessToken(new UserDetailsImpl(user));
        Ulid newRefreshToken = UlidCreator.getUlid(refreshTokenExpiryDate.getTime());

        sessionToUpdate.setActiveAccessToken(newAccessToken);
        sessionToUpdate.setActiveRefreshToken(newRefreshToken.toString());
        sessionToUpdate.setLastModifiedDate(new Date());
        sessionToUpdate.increaseTokenRefreshCount();

        userSessionDetailRepository.save(sessionToUpdate);
        return JwtAuthenticationResponse.builder()
                .accessToken(newAccessToken)
                .refreshToken(newRefreshToken.toString())
                .build();
    }

    private void throwExceptionIfAccessTokenIsNotExpired(String accessToken) {
        Date accessTokenExpiredAt = jwtService.getTokenExpiryFromExpiredJWT(accessToken);
        if (accessTokenExpiredAt.after(new Date())) {
            throw new JwtSecurityException(
                    REFRESH_TOKEN_ONLY_ALLOWED_WITH_EXPIRED_TOKEN,
                    "Refreshing The Token Is Only Allowed When Access Token Is Expired"
            );
        }
    }

    private static Optional<Session> findInOldSessions(List<Session> oldSessions,
                                                       String accessToken,
                                                       String refreshToken) {
        return oldSessions.stream()
                .filter(userSessionDetail -> {
                    String activeAccessToken = userSessionDetail.getActiveAccessToken();
                    String activeRefreshToken = userSessionDetail.getActiveRefreshToken();

                    return StringUtils.equals(accessToken, activeAccessToken) &&
                            StringUtils.equals(refreshToken, activeRefreshToken);
                }).findFirst();
    }

    private static void validateRefreshTokenAsULID(String refreshToken) {
        if (BooleanUtils.isNotTrue(Ulid.isValid(refreshToken))) {
            throw new JwtSecurityException(
                JwtSecurityException.JWTErrorCode.INVALID_REFRESH_TOKEN,
                "Invalid Refresh Token Provided"
            );
        }

        Date refreshTokenValidity = new Date(Ulid.from(refreshToken).getTime());
        if (refreshTokenValidity.before(new Date())) {
            throw new JwtSecurityException(
                    JwtSecurityException.JWTErrorCode.REFRESH_TOKEN_EXPIRED,
                    "Refresh Token Is Expired, Create New Login Request"
            );
        }
    }

    @Transactional
    public JwtAuthenticationResponse signinExclusively(SigninRequest request) {
        authenticationManager.authenticate(
            new UsernamePasswordAuthenticationToken(request.getUserName(), request.getPassword())
        );

        User user = userRepository
                .findByEmail(request.getUserName())
                .orElseThrow(
                    () -> new JwtSecurityException(
                        JwtSecurityException.JWTErrorCode.USER_NOT_FOUND,
                        "Invalid email or password"
                    )
                );

        List<Session> sessions = user.getSessions();
        if (CollectionUtils.isNotEmpty(sessions)) {
            userSessionDetailRepository.deleteAll(sessions);
        }

        var tokenMappedByType = jwtService.generateBothToken(new UserDetailsImpl(user));
        saveLoginSession(tokenMappedByType, user);

        return JwtAuthenticationResponse.builder()
                .accessToken(tokenMappedByType.get(TokenType.ACCESS_TOKEN))
                .refreshToken(tokenMappedByType.get(TokenType.REFRESH_TOKEN))
                .userName(request.getUserName())
                .loggedOutSessions(sessions)
                .build();
    }

    @Transactional
    public String logout(LogOutRequest logOutRequest) {
        String accessToken = logOutRequest.getAccessToken();
        String refreshToken = logOutRequest.getRefreshToken();

        String userName = jwtService.getUserNameFromExpiredJWT(accessToken);

        User user = userRepository.findByEmail(userName).orElseThrow(() ->
                new JwtSecurityException(
                        JwtSecurityException.JWTErrorCode.USER_NOT_FOUND,
                        "User Not Found With UserName:: "
                )
        );

        List<Session> sessions = user.getSessions();

        Optional<Session> optionalUserSessionDetail = findInOldSessions(sessions, accessToken, refreshToken);

        if (optionalUserSessionDetail.isEmpty()) {
            throw new JwtSecurityException(
                JwtSecurityException.JWTErrorCode.SESSION_NOT_FOUND,
                "User Session Not Found"
            );
        }

        Session session = optionalUserSessionDetail.get();
        userSessionDetailRepository.delete(session);

        return userName;
    }
}