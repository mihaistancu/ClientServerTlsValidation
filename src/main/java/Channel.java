import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.ProtocolException;
import java.net.URL;
import java.net.URLConnection;

public class Channel {
    public static void setRequestMethod(HttpURLConnection connection, String method) {
        try {
            connection.setRequestMethod(method);
        } catch (ProtocolException e) {
            throw new RuntimeException(e);
        }
    }

    public static URLConnection getUrlConnection(String uri) {
        try {
            return new URL(uri).openConnection();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public static int getResponseCode(HttpURLConnection connection) {
        try {
            return connection.getResponseCode();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public static InputStream getInputStream(HttpURLConnection connection) {
        try {
            return connection.getInputStream();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public static OutputStream getOutputStream(HttpURLConnection connection) {
        try {
            return connection.getOutputStream();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}
