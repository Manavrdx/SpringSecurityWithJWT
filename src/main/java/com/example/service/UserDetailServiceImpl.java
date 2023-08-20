package com.example.service;

import com.example.entity.User;
import com.example.repository.UserRepository;
import com.example.security.dto.UserDetailsImpl;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class UserDetailServiceImpl implements UserDetailsService {
    private static final String USER_NOT_FOUND_MSG = "User Not Found With UserName:: %s";
    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepository.findByEmail(username).orElseThrow(
                () -> new UsernameNotFoundException(USER_NOT_FOUND_MSG.formatted(username))
        );
        return new UserDetailsImpl(user);
    }
}