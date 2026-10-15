// Semgrep rule tests for skills/sk-api/rules/api.yml (Java).
@RestController
// ruleid: sk-cors-wildcard-credentials-other
@CrossOrigin(origins = "*", allowCredentials = "true")
public class Api {
    // ruleid: sk-hardcoded-secret-go-java
    private static final String JWT_SECRET = "java-hardcoded-secret-value";

    public List<User> find(String name) {
        // ruleid: sk-sql-string-building
        return jdbc.query("SELECT * FROM users WHERE name = '" + name + "'", mapper);
    }
}
