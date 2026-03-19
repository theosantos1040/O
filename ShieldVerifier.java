import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;

public class ShieldVerifier {
    private final String apiBase;
    private final String siteKey;
    private final String secretKey;

    public ShieldVerifier(String apiBase, String siteKey, String secretKey) {
        this.apiBase = apiBase;
        this.siteKey = siteKey;
        this.secretKey = secretKey;
    }

    public boolean verify(String token, String route) throws Exception {
        URL url = new URL(apiBase + "/api/verify");
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("POST");
        conn.setDoOutput(true);
        conn.setRequestProperty("Content-Type", "application/json");
        conn.setRequestProperty("Accept", "application/json");

        String body = String.format(
            "{\"siteKey\":\"%s\",\"secretKey\":\"%s\",\"token\":\"%s\",\"route\":\"%s\"}",
            siteKey, secretKey, token, route
        );

        try (OutputStream os = conn.getOutputStream()) {
            os.write(body.getBytes(StandardCharsets.UTF_8));
        }

        int code = conn.getResponseCode();
        return code >= 200 && code < 300;
    }
}
