package dev.hedgerow.oracle.controller;

import dev.hedgerow.oracle.service.AssistantService;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * First hop for V-JA-13 (/ask -> SqlAgent -> QueryRunner) and V-JA-14
 * (/act -> AgentLoop -> ShellTool). Neither the LLM call nor the sink is
 * visible from this file -- both are two hops away, the controller ->
 * service -> tool/graph-node shape the Java survey found in 15 of 16 real
 * sink files (BACKLOG.md, "Java cross-file reality").
 */
@RestController
public class ChatController {

    private final AssistantService assistantService;

    public ChatController(AssistantService assistantService) {
        this.assistantService = assistantService;
    }

    @PostMapping("/ask")
    public Object ask(@RequestParam String q) {
        return assistantService.ask(q);
    }

    @PostMapping("/act")
    public String act(@RequestParam String task) throws Exception {
        return assistantService.dispatch(task);
    }
}
