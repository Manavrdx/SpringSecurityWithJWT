package com.example.repository;

import com.example.entity.Session;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.Date;
import java.util.List;

@Repository
public interface UserSessionDetailRepository extends JpaRepository<Session, Long> {

    @Query(
        value = """
            select
                usd.id
            from sessions usd
            where
                usd.refresh_token_expire_date < :currentDate
            limit :maxResults
        """,
        nativeQuery = true
    )
    List<Long> findExpiredSessionIds(Date currentDate, Integer maxResults);

    @Modifying
    @Query("delete from Session b where b.id in :ids")
    Integer deleteByIds(@Param("ids") List<Long> ids);
}