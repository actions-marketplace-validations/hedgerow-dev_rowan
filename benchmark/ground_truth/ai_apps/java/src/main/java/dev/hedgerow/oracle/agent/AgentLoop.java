package dev.hedgerow.oracle.agent;

import dev.hedgerow.oracle.tool.ShellTool;
import org.springframework.ai.chat.client.ChatClient;
import org.springframework.stereotype.Component;

/**
 * V-JA-14 (tnt-ja-ai-toolexec-001, cross-file / JG-13 acceptance target):
 * third hop. A minimal single-step agent loop: the LLM is asked to name the
 * shell command it wants run, and the loop dispatches straight to
 * ShellTool.run without an intermediate @Tool-annotated call boundary --
 * the shape the survey called "@Tool dispatch by the agent loop" rather
 * than a direct model-invoked tool call.
 */
@Component
public class AgentLoop {

    private final ChatClient chatClient;
    private final ShellTool shellTool;

    public AgentLoop(ChatClient chatClient, ShellTool shellTool) {
        this.chatClient = chatClient;
        this.shellTool = shellTool;
    }

    public String run(String task) throws Exception {
        String command = chatClient.prompt()
                .user("Name the single shell command to accomplish: " + task)
                .call()
                .content();
        return shellTool.run(command);
    }
}
