import java.nio.file.Files;
import java.nio.file.Paths;

import dev.langchain4j.agent.tool.P;
import dev.langchain4j.agent.tool.Tool;

// LangChain4j @Tool parameter used as a file name under a fixed directory (tnt-ja-ai-toolpath-001, CWE-22).
public class ToolPath {
    private static final String FILE_DIR = "/srv/agent/files";

    @Tool("Read content from a file")
    public String readFile(@P("Name of the file to read") String fileName) throws Exception {
        return Files.readString(Paths.get(FILE_DIR + "/" + fileName));
    }
}
