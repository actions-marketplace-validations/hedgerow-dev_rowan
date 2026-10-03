import org.springframework.web.bind.annotation.RequestParam;
import org.neo4j.driver.Session;

// A request value is interpolated into a Cypher query run against Neo4j
// (tnt-ja-ai-vectorq-001, CWE-943).
public class VectorFilter {
    public void run(@RequestParam String cypher, Session session) {
        session.run(cypher);
    }
}
