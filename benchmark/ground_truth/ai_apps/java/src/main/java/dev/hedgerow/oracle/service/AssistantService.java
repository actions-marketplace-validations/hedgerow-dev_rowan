package dev.hedgerow.oracle.service;

import dev.hedgerow.oracle.agent.AgentLoop;
import dev.hedgerow.oracle.agent.SqlAgent;
import org.springframework.stereotype.Service;

/**
 * Second hop for both V-JA-13 and V-JA-14: the service layer between the
 * controller and the agent classes that actually talk to the LLM.
 */
@Service
public class AssistantService {

    private final SqlAgent sqlAgent;
    private final AgentLoop agentLoop;

    public AssistantService(SqlAgent sqlAgent, AgentLoop agentLoop) {
        this.sqlAgent = sqlAgent;
        this.agentLoop = agentLoop;
    }

    public Object ask(String question) {
        return sqlAgent.run(question);
    }

    public String dispatch(String task) throws Exception {
        return agentLoop.run(task);
    }
}
