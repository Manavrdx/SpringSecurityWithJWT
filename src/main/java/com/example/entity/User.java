package com.example.entity;

import java.util.List;

import com.example.enums.Role;
import lombok.*;

import jakarta.persistence.*;

@Builder
@NoArgsConstructor
@Entity
@Table(name = "user")
@Getter
@Setter
@AllArgsConstructor
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String firstName;

    private String lastName;

    @Column(unique = true)
    private String email;

    private String password;

    @Enumerated(EnumType.STRING)
    private Role role;

    @OneToMany(mappedBy = "user")
    private List<Session> sessions;
}