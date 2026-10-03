import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.ai.chat.messages.SystemMessage;

// A request value becomes the system prompt (tnt-ja-ai-sysprompt-001, CWE-20).
public class Sysprompt {
    public void configure(@RequestParam String persona) {
        new SystemMessage(persona);
    }
}
