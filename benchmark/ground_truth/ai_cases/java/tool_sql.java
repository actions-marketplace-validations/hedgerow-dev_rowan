import java.util.List;
import java.util.Map;

import org.springframework.ai.tool.annotation.Tool;
import org.springframework.jdbc.core.JdbcTemplate;

// Spring AI @Tool parameter concatenated into JdbcTemplate query text (tnt-ja-ai-toolsql-001, CWE-89).
public class ToolSql {
    private final JdbcTemplate jdbcTemplate;

    public ToolSql(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    @Tool(description = "Find customers by name")
    public List<Map<String, Object>> findCustomers(String name) {
        return jdbcTemplate.queryForList("SELECT * FROM customers WHERE name = '" + name + "'");
    }
}
