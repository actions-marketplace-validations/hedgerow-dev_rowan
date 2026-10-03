package dev.hedgerow.oracle.tool;

import org.springframework.ai.tool.annotation.Tool;
import org.springframework.ai.tool.annotation.ToolParam;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.Set;

/**
 * D-JA-01: looks like ShellTool but the model-chosen action is checked
 * against a fixed allowlist before it ever reaches ProcessBuilder.
 */
@Component
public class SafeShellTool {

    private static final Set<String> ALLOWED_ACTIONS = Set.of("status", "restart-worker", "flush-cache");

    @Tool(description = "Run a whitelisted maintenance action")
    public String runAction(@ToolParam(description = "one of the allowed action names") String action) throws IOException {
        if (!ALLOWED_ACTIONS.contains(action)) {
            throw new IllegalArgumentException("unknown action: " + action);
        }
        ProcessBuilder pb = new ProcessBuilder("/opt/oracle/bin/" + action + ".sh");
        Process proc = pb.start();
        return "started pid " + proc.pid();
    }
}
