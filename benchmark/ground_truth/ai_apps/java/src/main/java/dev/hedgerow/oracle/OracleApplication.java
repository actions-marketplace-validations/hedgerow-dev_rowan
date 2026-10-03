package dev.hedgerow.oracle;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Entry point for the Oracle app (benchmark/ground_truth/ai_apps/java, JG-11).
 * Source only -- this project is never built or run, only scanned.
 */
@SpringBootApplication
public class OracleApplication {

    public static void main(String[] args) {
        SpringApplication.run(OracleApplication.class, args);
    }
}
