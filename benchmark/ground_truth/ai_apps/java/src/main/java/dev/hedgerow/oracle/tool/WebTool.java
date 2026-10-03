package dev.hedgerow.oracle.tool;

import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.springframework.ai.tool.annotation.Tool;
import org.springframework.ai.tool.annotation.ToolParam;
import org.springframework.stereotype.Component;

import java.io.IOException;

/**
 * V-JA-04 (tnt-ja-ai-toolssrf-001): the model picks the URL to fetch, with
 * no allowlist or scheme check -- reaches internal metadata endpoints.
 */
@Component
public class WebTool {

    @Tool(description = "Fetch and summarize a web page")
    public String fetchPage(@ToolParam(description = "URL to fetch") String url) throws IOException {
        Document doc = Jsoup.connect(url).get();
        return doc.title() + "\n" + doc.text();
    }
}
