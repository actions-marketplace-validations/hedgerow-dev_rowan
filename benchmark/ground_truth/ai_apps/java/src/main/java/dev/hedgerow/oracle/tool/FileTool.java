package dev.hedgerow.oracle.tool;

import org.springframework.ai.tool.annotation.Tool;
import org.springframework.ai.tool.annotation.ToolParam;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;

/**
 * V-JA-02 (tnt-ja-ai-toolpath-001): `fileName` is model-controlled and
 * concatenated into a path with no containment check.
 */
@Component
public class FileTool {

    private static final String NOTES_DIR = "/var/lib/oracle/notes";

    @Tool(description = "Read a saved note by file name")
    public String readNote(@ToolParam(description = "note file name") String fileName) throws IOException {
        return Files.readString(Paths.get(NOTES_DIR + "/" + fileName));
    }
}
