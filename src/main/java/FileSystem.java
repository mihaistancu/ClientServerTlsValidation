import java.io.*;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.function.BiFunction;
import java.util.function.Consumer;

public class FileSystem {
    public static RandomAccessFile getRandomAccessFile(String filePath) {
        try {
            return new RandomAccessFile(filePath, "r");
        } catch (FileNotFoundException e) {
            throw new RuntimeException(e);
        }
    }

    public static String readString(String filePath) {
        try {
            return Files.readString(Path.of(filePath));
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public static void seek(RandomAccessFile file, long offset) {
        try {
            file.seek(offset);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public static void transfer(String path, OutputStream outputStream) {
        try (FileInputStream fileInputStream = new FileInputStream(path)) {
            fileInputStream.transferTo(outputStream);
        }
        catch (IOException exception) {
            throw new RuntimeException(exception);
        }
    }

    public static FileInputStream getFileInputStream(String path) {
        try {
            return new FileInputStream(path);
        } catch (FileNotFoundException e) {
            throw new RuntimeException(e);
        }
    }

    public static FileOutputStream getFileOutputStream(String path) {
        try {
            return new FileOutputStream(path);
        } catch (FileNotFoundException e) {
            throw new RuntimeException(e);
        }
    }

    public static byte[] readAllBytes(String path) {
        try {
            return Files.readAllBytes(Path.of(path));
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public static void write(String path, byte[] bytes) {
        try {
            Files.write(Path.of(path), bytes);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public static void write(String path, String content) {
        try {
            Files.writeString(Path.of(path), content);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public static void delete(String path) {
        try {
            Files.delete(Path.of(path));
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public static void createDirectory(String path) {
        try {
            Files.createDirectories(Path.of(path));
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public static DirectoryStream<Path> newDirectoryStream(String directory, String prefix) {
        try {
            return Files.newDirectoryStream(Path.of(directory), prefix);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public static <T> T reduce(DirectoryStream<Path> directoryStream, BiFunction<T, Path, T> handler, T initial) {
        try (directoryStream) {
            T result = initial;
            for (Path path: directoryStream) {
                result = handler.apply(result, path);
            }
            return result;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static BufferedWriter getBufferedWriter(Path path) {
        try {
            return Files.newBufferedWriter(path);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public static Reader getFileReader(String path) {
        try {
            return new FileReader(path);
        } catch (FileNotFoundException e) {
            throw new RuntimeException(e);
        }
    }

    public static void forEachFileIn(Path directory, Consumer<Path> fileHandler) {
        try (DirectoryStream<Path> stream = Files.newDirectoryStream(directory)) {
            for (Path path : stream) {
                fileHandler.accept(path);
            }
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}
