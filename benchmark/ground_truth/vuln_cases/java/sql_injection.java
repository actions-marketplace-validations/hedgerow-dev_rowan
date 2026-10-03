import java.sql.Statement;

public class UserDao {
    public void findUser(Statement stmt, String userId) throws Exception {
        stmt.executeQuery("SELECT * FROM users WHERE id = " + userId);
    }
}
