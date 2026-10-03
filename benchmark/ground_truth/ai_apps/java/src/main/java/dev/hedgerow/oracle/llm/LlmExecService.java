package dev.hedgerow.oracle.llm;

import org.springframework.ai.chat.client.ChatClient;
import org.springframework.stereotype.Service;

import java.io.IOException;

/**
 * V-JA-06 (tnt-ja-ai-llmout-exec-001): the LLM is asked to produce a shell
 * one-liner and the answer is executed verbatim.
 */
@Service
public class LlmExecService {

    private final ChatClient chatClient;

    public LlmExecService(ChatClient chatClient) {
        this.chatClient = chatClient;
    }

    public String askAndRun(String task) throws IOException {
        String shellOneLiner = chatClient.prompt()
                .user("Give me a single shell command that: " + task)
                .call()
                .content();
        ProcessBuilder pb = new ProcessBuilder("sh", "-c", shellOneLiner);
        Process proc = pb.start();
        return "started pid " + proc.pid();
    }
}
