package dev.hedgerow.oracle.controller;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.SafeConstructor;

import java.util.Map;

/**
 * D-JA-04: looks like YamlConfigController but loads with SafeConstructor,
 * which restricts deserialization to plain Java scalars/collections.
 */
@RestController
public class YamlSafeController {

    @PostMapping("/config/pipeline-safe")
    public Map<String, Object> loadConfig(@RequestBody String body) {
        Yaml yaml = new Yaml(new SafeConstructor(new org.yaml.snakeyaml.LoaderOptions()));
        return yaml.load(body);
    }
}
