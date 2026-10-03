import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.ai.mcp.client.transport.StdioMcpTransport;

// A request value becomes the MCP stdio command (tnt-ja-ai-mcpcmd-001, CWE-78).
public class Mcpcmd {
    public void connect(@RequestParam String cmd, StdioMcpTransport transport) {
        transport.command(cmd);
    }
}
