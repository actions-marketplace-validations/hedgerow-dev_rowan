import java.io.File;
import java.nio.file.Files;

public class ReportStore {
    public byte[] read(String name) throws Exception {
        File f = new File("/var/reports/" + name);
        return Files.readAllBytes(f.toPath());
    }
}
