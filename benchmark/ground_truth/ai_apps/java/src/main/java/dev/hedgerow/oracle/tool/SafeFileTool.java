package dev.hedgerow.oracle.tool;

import org.springframework.ai.tool.annotation.Tool;
import org.springframework.ai.tool.annotation.ToolParam;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * D-JA-02: looks like FileTool but resolves against the notes directory and
 * refuses to serve anything that escapes it via a startsWith containment
 * check on the resolved, normalized path.
 */
@Component
public class SafeFileTool {

    private static final Path NOTES_DIR = Path.of("/var/lib/oracle/notes").toAbsolutePath().normalize();

    @Tool(description = "Read a saved note by file name, path-checked")
    public String readNote(@ToolParam(description = "note file name") String fileName) throws IOException {
        Path resolved = NOTES_DIR.resolve(fileName).normalize();
        if (!resolved.startsWith(NOTES_DIR)) {
            throw new SecurityException("path escapes notes directory");
        }
        return Files.readString(resolved);
    }
}
