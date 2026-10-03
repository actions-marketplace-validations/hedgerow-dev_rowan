package dev.hedgerow.oracle.llm;

import org.springframework.ai.chat.client.ChatClient;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;

/**
 * V-JA-08 (tnt-ja-ai-llmout-path-001): the LLM names a "relevant log file"
 * and the app reads it from disk with no containment check.
 */
@Service
public class LlmPathService {

    private final ChatClient chatClient;

    public LlmPathService(ChatClient chatClient) {
        this.chatClient = chatClient;
    }

    public String askAndReadLog(String question) throws IOException {
        String logPath = chatClient.prompt()
                .user("Which log file under /var/log/oracle is relevant to: " + question)
                .call()
                .content();
        return Files.readString(Paths.get(logPath));
    }
}
