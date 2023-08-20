package com.example.security.helper;

import com.example.repository.UserSessionDetailRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.collections4.CollectionUtils;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Date;
import java.util.List;

import static java.util.concurrent.TimeUnit.MINUTES;

@Service
@Slf4j
@RequiredArgsConstructor
public class StaleSessionRemover {
    private static final int FIXED_DELAY = 1;
    private static final int BATCH_SIZE = 100;

    private final UserSessionDetailRepository userSessionDetailRepository;

    @Transactional
    @Scheduled(fixedDelay = FIXED_DELAY, timeUnit = MINUTES)
    public void removeStaleSession() {
        try {
            List<Long> expiredSessionIds =
                    userSessionDetailRepository.findExpiredSessionIds(new Date(), BATCH_SIZE);

            if (CollectionUtils.isNotEmpty(expiredSessionIds)) {
                Integer rowsEffected = userSessionDetailRepository.deleteByIds(expiredSessionIds);
                log.debug("Number Of Stale Session Deleted:: {}", rowsEffected);
            }
        } catch (Exception exception) {
            log.error("Exception In Removing Stale Sessions:: ", exception);
        }
    }
}
