import java.io.IOException;
import java.util.stream.Collectors;

public class JavaProcess {
    private Process process;

    public JavaProcess(String... params) {
        startProcess(params);
    }

    private void startProcess(String... params) {
        ProcessBuilder pb = new ProcessBuilder("java");
        for (String param : params) {
            pb.command().add(param);
        }
        System.out.println(pb.command().stream().collect(Collectors.joining(" ")));
        pb.inheritIO();
        pb.redirectErrorStream(true);
        process = start(pb);
    }

    public static Process start(ProcessBuilder pb) {
        try {
            return pb.start();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public void waitToFinish() {
        try {
           process.waitFor();
        } catch (InterruptedException e) {
            throw new RuntimeException(e);
        }
    }

    public void stop() {
        process.destroy();
    }
}
