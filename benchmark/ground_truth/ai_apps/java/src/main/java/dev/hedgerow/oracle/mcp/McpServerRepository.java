package dev.hedgerow.oracle.mcp;

import org.springframework.data.jpa.repository.JpaRepository;

public interface McpServerRepository extends JpaRepository<McpServerEntity, Long> {
}
