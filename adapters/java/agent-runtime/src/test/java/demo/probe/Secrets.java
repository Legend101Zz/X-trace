package demo.probe;

public class Secrets {
  public String login(String user, String password) {
    String greeting = "hello " + user;
    String sessionToken = "S3CR3T-" + password;
    int length = greeting.length();
    return greeting + length + sessionToken.length();
  }
}
