package dev.hedgerow.oracle.controller;

import org.springframework.ai.chat.client.ChatClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * V-JA-11 (tnt-ja-ai-sysprompt-001): a request parameter is placed directly
 * into the system prompt, letting a caller override the assistant's
 * instructions rather than only its user turn.
 */
@RestController
public class PromptController {

    private final ChatClient chatClient;

    public PromptController(ChatClient chatClient) {
        this.chatClient = chatClient;
    }

    @GetMapping("/assist")
    public String assist(@RequestParam String persona, @RequestParam String q) {
        return chatClient.prompt()
                .system(persona)
                .user(q)
                .call()
                .content();
    }
}
