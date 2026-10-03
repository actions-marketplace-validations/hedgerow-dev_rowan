import org.springframework.web.bind.annotation.RequestParam;
import org.yaml.snakeyaml.Yaml;

// A request value is loaded with SnakeYAML's unsafe default constructor
// (tnt-ja-ai-yaml-001, CWE-502).
public class UnsafeYaml {
    public void load(@RequestParam String body) {
        Yaml yaml = new Yaml();
        yaml.load(body);
    }
}
