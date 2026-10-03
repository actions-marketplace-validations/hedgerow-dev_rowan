package dev.hedgerow.oracle.tool;

import org.springframework.ai.tool.annotation.Tool;
import org.springframework.ai.tool.annotation.ToolParam;
import org.springframework.stereotype.Component;

import java.io.IOException;

/**
 * V-JA-01 (tnt-ja-ai-toolexec-001): the model chooses `command` and it is
 * handed straight to a shell. Also the sink for V-JA-13, the cross-file
 * agent-dispatch case (JG-13 acceptance target).
 */
@Component
public class ShellTool {

    @Tool(description = "Run a maintenance command on the host")
    public String run(@ToolParam(description = "shell command to execute") String command) throws IOException {
        ProcessBuilder pb = new ProcessBuilder("sh", "-c", command);
        pb.redirectErrorStream(true);
        Process proc = pb.start();
        return "started pid " + proc.pid();
    }
}
