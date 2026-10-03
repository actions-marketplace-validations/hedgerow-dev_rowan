import org.jsoup.Jsoup;
import org.springframework.ai.tool.annotation.Tool;
import org.springframework.ai.tool.annotation.ToolParam;

// Spring AI @Tool parameter used as the URL of an outbound fetch (tnt-ja-ai-toolssrf-001, CWE-918).
public class ToolSsrf {
    @Tool(description = "Scrape the content of a web page")
    public String scrapeWebPage(@ToolParam(description = "URL of the web page to scrape") String url) throws Exception {
        return Jsoup.connect(url).get().html();
    }
}
