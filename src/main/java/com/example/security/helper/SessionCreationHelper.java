package com.example.security.helper;

import com.example.properties.JwtTokenProperty;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class SessionCreationHelper {
    private final JwtTokenProperty jwtTokenProperty;

    public boolean canCreateNewSession(int numberOfSessionInDb) {
        Integer allowedSessionCount = jwtTokenProperty.getAllowedSessionCount();
        boolean autoLogoutFromOtherDeviceOnOverflowSessionCount =
                jwtTokenProperty.isAutoLogoutFromOtherDeviceOnOverflowSessionCount();

        boolean thereIsSlotForAnotherSession = numberOfSessionInDb < allowedSessionCount;
        return thereIsSlotForAnotherSession || autoLogoutFromOtherDeviceOnOverflowSessionCount;
    }

    public boolean doWeNeedToRemoveOldSession(int numberOfSessionInDB) {
        Integer allowedSessionCount = jwtTokenProperty.getAllowedSessionCount();
        boolean autoLogoutFromOtherDeviceOnOverflowSessionCount =
                jwtTokenProperty.isAutoLogoutFromOtherDeviceOnOverflowSessionCount();
        return numberOfSessionInDB >= allowedSessionCount &&
                autoLogoutFromOtherDeviceOnOverflowSessionCount;
    }

    public Integer getAllowedSessionCount() {
        return jwtTokenProperty.getAllowedSessionCount();
    }
}
