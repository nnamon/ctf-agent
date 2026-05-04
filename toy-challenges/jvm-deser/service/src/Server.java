import java.io.*;
import java.net.*;

public class Server {
    public static void main(String[] args) throws IOException {
        int port = Integer.parseInt(System.getenv().getOrDefault("PORT", "1337"));
        try (ServerSocket s = new ServerSocket(port)) {
            System.out.println("token-service listening on " + port);
            while (true) {
                handle(s.accept());
            }
        }
    }

    static void handle(Socket c) {
        try (ObjectInputStream in = new ObjectInputStream(c.getInputStream());
             PrintWriter out = new PrintWriter(c.getOutputStream(), true)) {
            Object obj = in.readObject();
            out.println("ok: " + obj);
        } catch (Exception e) {
            try (PrintWriter out = new PrintWriter(c.getOutputStream(), true)) {
                out.println("error: " + e);
            } catch (IOException ignored) {}
        } finally {
            try { c.close(); } catch (IOException ignored) {}
        }
    }
}
