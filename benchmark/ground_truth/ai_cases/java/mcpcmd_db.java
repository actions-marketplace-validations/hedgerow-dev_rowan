import org.springframework.ai.mcp.client.transport.StdioMcpTransport;

// The MCP stdio command comes from a DB row's getter, not a literal
// (tnt-ja-ai-mcpcmd-002, CWE-78; the aideepin UserMcpService shape).
public class McpcmdDb {
    public void connect(StdioMcpTransport transport, McpServerEntity entity) {
        transport.command(entity.getStdioCommand());
    }
}
