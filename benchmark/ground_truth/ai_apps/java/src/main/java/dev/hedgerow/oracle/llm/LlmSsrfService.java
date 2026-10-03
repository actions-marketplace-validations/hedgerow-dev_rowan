package dev.hedgerow.oracle.llm;

import org.springframework.ai.chat.client.ChatClient;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

/**
 * V-JA-07 (tnt-ja-ai-llmout-ssrf-001): the LLM proposes a "source URL" for a
 * citation and the app fetches it server-side with no allowlist.
 */
@Service
public class LlmSsrfService {

    private final ChatClient chatClient;
    private final RestTemplate restTemplate;

    public LlmSsrfService(ChatClient chatClient, RestTemplate restTemplate) {
        this.chatClient = chatClient;
        this.restTemplate = restTemplate;
    }

    public String askAndFetchCitation(String question) {
        String citationUrl = chatClient.prompt()
                .user("Give me one URL that supports this claim: " + question)
                .call()
                .content();
        return restTemplate.getForObject(citationUrl, String.class);
    }
}
