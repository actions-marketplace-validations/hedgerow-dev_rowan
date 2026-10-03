package dev.hedgerow.oracle.controller;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import org.yaml.snakeyaml.Yaml;

import java.util.Map;

/**
 * V-JA-10 (tnt-ja-ai-yaml-001): the request body is loaded with the default
 * (unsafe) SnakeYAML constructor, which can instantiate arbitrary Java
 * types (the SnakeYAML CVE-2022-1471 class).
 */
@RestController
public class YamlConfigController {

    @PostMapping("/config/pipeline")
    public Map<String, Object> loadConfig(@RequestBody String body) {
        Yaml yaml = new Yaml();
        return yaml.load(body);
    }
}
