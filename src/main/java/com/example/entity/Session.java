package com.example.entity;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;

import java.util.Date;

@Entity
@Getter
@Setter
@Table(name = "sessions")
public class Session {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id", nullable = false, updatable = false)
    private Long id;

    @Column(name = "active_access_token", nullable = false)
    private String activeAccessToken;

    @Column(name = "active_refresh_token", nullable = false)
    private String activeRefreshToken;

    @Column(name = "refresh_token_expire_date", nullable = false)
    private Date refreshTokenExpiryDate;

    @ManyToOne
    @JoinColumn(name = "token_issued_to_user_id")
    private User user;

    @Column(name = "created_date")
    private Date createdDate;

    @Column(name = "last_modified_date")
    private Date lastModifiedDate;

    @Column(name = "token_refresh_count")
    private Integer tokenRefreshCount = 0;

    public void increaseTokenRefreshCount() {
        tokenRefreshCount = tokenRefreshCount + 1;
    }

    public boolean refreshDateCrossed() {
        return refreshTokenExpiryDate.before(new Date());
    }
}
