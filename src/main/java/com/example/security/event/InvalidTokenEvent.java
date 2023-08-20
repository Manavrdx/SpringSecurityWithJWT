package com.example.security.event;

import java.io.Serial;
import java.time.Instant;
import java.util.Date;

import com.example.security.dto.LogOutRequest;
import org.springframework.context.ApplicationEvent;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class InvalidTokenEvent extends ApplicationEvent {
	@Serial
    private static final long serialVersionUID = 1L;

	private final String userEmail;
    private final String accessToken;
    private final String refreshToken;
    private final Date eventTime;
    private String metaData;

    public InvalidTokenEvent(String userEmail, LogOutRequest logOutRequest) {
        super(userEmail);
        this.userEmail = userEmail;
        this.accessToken = logOutRequest.getAccessToken();
        this.refreshToken = logOutRequest.getRefreshToken();
        this.eventTime = Date.from(Instant.now());
    }
}