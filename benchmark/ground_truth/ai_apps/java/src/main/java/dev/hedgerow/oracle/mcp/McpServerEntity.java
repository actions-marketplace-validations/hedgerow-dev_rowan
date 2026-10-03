package dev.hedgerow.oracle.mcp;

import jakarta.persistence.Entity;
import jakarta.persistence.Id;

/**
 * A user-editable row describing an MCP server to launch locally. `command`
 * is set through the admin UI's PUT /mcp-servers/{id} endpoint (out of
 * scope for this snippet) and is trusted verbatim by McpLauncherService.
 */
@Entity
public class McpServerEntity {

    @Id
    private Long id;

    private String name;

    private String command;

    public Long getId() {
        return id;
    }

    public String getName() {
        return name;
    }

    public String getCommand() {
        return command;
    }
}
