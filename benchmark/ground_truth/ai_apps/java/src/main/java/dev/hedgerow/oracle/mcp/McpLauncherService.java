package dev.hedgerow.oracle.mcp;

import io.modelcontextprotocol.client.transport.StdioMcpTransport;
import org.springframework.stereotype.Service;

/**
 * V-JA-12 (tnt-ja-ai-mcpcmd-002): the launch command comes back from a JPA
 * row a user configured earlier, not the current request -- the taint hop
 * is a DB round-trip rather than a direct parameter, the same class of
 * source the JG-06 rule targets (config/DB value -> stdio transport
 * command), just one hop further than the request-parameter variant.
 */
@Service
public class McpLauncherService {

    private final McpServerRepository repository;

    public McpLauncherService(McpServerRepository repository) {
        this.repository = repository;
    }

    public void launch(Long serverId) {
        McpServerEntity row = repository.findById(serverId)
                .orElseThrow(() -> new IllegalArgumentException("no such server: " + serverId));
        StdioMcpTransport transport = StdioMcpTransport.builder()
                .command(row.getCommand())
                .build();
        transport.connect();
    }
}
