// WhitelistService.java
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.HashSet;
import java.util.Set;

public class WhitelistService {

    private final Set<String> whitelistedIps = new HashSet<>();

    public WhitelistService(String whitelistResourcePath) {
        loadWhitelist(whitelistResourcePath);
    }

    private void loadWhitelist(String resourcePath) {
        try (InputStream is = getClass().getResourceAsStream(resourcePath)) {
            if (is == null) {
                // pas de fichier, whitelist vide
                return;
            }
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(is))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    String trimmed = line.trim();
                    if (!trimmed.isEmpty() && !trimmed.startsWith("#")) {
                        whitelistedIps.add(trimmed);
                    }
                }
            }
        } catch (IOException e) {
        }
    }

    public boolean isWhitelisted(String ip) {
        return whitelistedIps.contains(ip);
    }
}