import org.springframework.ai.tool.annotation.Tool;
import org.springframework.ai.tool.annotation.ToolParam;

// Spring AI @Tool parameter executed through a shell (tnt-ja-ai-toolexec-001, CWE-78).
public class ToolExec {
    @Tool(description = "Execute a command in the terminal")
    public String executeTerminalCommand(@ToolParam(description = "Command to execute") String command) throws Exception {
        Process process = new ProcessBuilder("sh", "-c", command).start();
        return String.valueOf(process.waitFor());
    }
}
