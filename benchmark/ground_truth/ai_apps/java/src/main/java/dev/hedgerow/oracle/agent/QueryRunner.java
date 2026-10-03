package dev.hedgerow.oracle.agent;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Map;

/**
 * Fourth hop of V-JA-13: the SQL text SqlAgent generated from the LLM's
 * answer finally reaches JdbcTemplate here, in a class the LLM call site
 * (SqlAgent) has never heard of.
 */
@Component
public class QueryRunner {

    private final JdbcTemplate jdbcTemplate;

    public QueryRunner(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    public List<Map<String, Object>> execute(String sql) {
        return jdbcTemplate.queryForList(sql);
    }
}
