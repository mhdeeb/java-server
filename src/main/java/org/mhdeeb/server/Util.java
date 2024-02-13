package org.mhdeeb.server;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.math.RoundingMode;
import java.net.URI;
import java.net.URL;
import java.net.URLConnection;
import java.text.DecimalFormat;
import java.util.ArrayList;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

interface ByteTransformer<T> {
    public T transform(byte c);
}

public class Util {
    private Util() {
    }

    public static String cleanPath(String path) {
        return path.replace("\\", "/");
    }

    public static String extractData(JsonNode root) {
        JsonNode error = root.path("error");

        if (!error.isMissingNode() && error.asBoolean())
            return "(Unknown)";

        String name = root.path("country_name").asText();

        String org = root.path("org").asText();

        if (name.isEmpty() && org.isEmpty())
            return null;

        return name + " (" + org + ")";
    }

    @SuppressWarnings("unused")
    public static void printAll(BufferedInputStream in) throws IOException {
        char c;
        while ((c = (char) in.read()) != -1) {
            System.out.print(c);
        }
    }

    public static String getIPLookupData(String ip, ObjectMapper mapper) {
        try {
            File file = Extern.getIPLookupFile();

            JsonNode root = mapper.readTree(file);

            root = root.path(ip);

            return extractData(root);
        } catch (Exception e) {
            return null;
        }
    }

    public static void saveIP(JsonNode root, ObjectMapper mapper) throws IOException {
        File file = Extern.getIPLookupFile();

        String ip = root.path("ip").asText();

        ((ObjectNode) root).remove("ip");

        JsonNode fileRoot = mapper.readTree(file);

        try (FileWriter out = new FileWriter(file)) {
            if (fileRoot.isNull() || fileRoot.isMissingNode()) {
                ObjectNode newRoot = mapper.createObjectNode();
                newRoot.set(ip, root);
                mapper.writeValue(out, newRoot);
            } else {
                ((ObjectNode) fileRoot).set(ip, root);
                mapper.writeValue(out, fileRoot);
            }
        }
    }

    public static String getIPLookUp(String ip, ObjectMapper mapper) {

        String result = getIPLookupData(ip, mapper);

        if (result != null)
            return result;

        try {

            URI uri = new URI("https://ipapi.co/" + ip + "/json/");

            URL api = uri.toURL();

            URLConnection yc = api.openConnection();

            JsonFactory factory = mapper.getFactory();

            JsonParser jsonParser = factory.createParser(yc.getInputStream());

            JsonNode root = mapper.readTree(jsonParser);

            saveIP(root, mapper);

            return extractData(root);
        } catch (Exception e) {
            return "Unknown";
        }
    }

    public static String transformString(String input, ByteTransformer<String> s) {
        StringBuilder output = new StringBuilder();

        for (byte b : input.getBytes()) {
            output.append(s.transform(b));
        }

        return output.toString();
    }

    public static String toHex(String input) {
        return transformString(input, c -> String.format("%02x", c));
    }

    public static String millisecondsToDateString(long milliseconds) {
        long diff = System.currentTimeMillis() - milliseconds;
        if (diff < 1000)
            return "just now";
        diff /= 1000;
        if (diff < 60)
            return diff + " seconds ago";
        diff /= 60;
        if (diff < 60)
            return diff + " minutes ago";
        diff /= 60;
        if (diff < 24)
            return diff + " hours ago";
        return new java.text.SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new java.util.Date(milliseconds));
    }

    public static String sizeToString(long size) {
        DecimalFormat df = new DecimalFormat("#.##");
        df.setRoundingMode(RoundingMode.HALF_UP);
        if (size < 1024)
            return size + " B";
        else if (size < 1024 * 1024)
            return df.format(size / (double) 1024) + " KB";
        else if (size < (double) 1024 * 1024 * 1024)
            return df.format(size / (double) (1024 * 1024)) + " MB";
        else
            return df.format(size / (double) (1024 * 1024 * 1024)) + " GB";
    }

    public static void populateFilesList(File dir, List<String> filesListInDir) throws IOException {
        File[] files = dir.listFiles();
        for (File file : files) {
            if (file.isFile())
                filesListInDir.add(file.getAbsolutePath());
            else
                populateFilesList(file, filesListInDir);
        }
    }

    private static void zipDirectory(File dir, File zipFile) throws IOException {
        List<String> filesListInDir = new ArrayList<>();

        populateFilesList(dir, filesListInDir);

        try (ZipOutputStream zos = new ZipOutputStream(new FileOutputStream(zipFile));) {
            for (String filePath : filesListInDir) {
                ZipEntry ze = new ZipEntry(filePath.substring(dir.getAbsolutePath().length() + 1, filePath.length()));

                zos.putNextEntry(ze);

                try (FileInputStream fis = new FileInputStream(filePath);) {
                    byte[] buffer = new byte[1024];

                    int len;
                    while ((len = fis.read(buffer)) > 0) {
                        zos.write(buffer, 0, len);
                    }
                }
                zos.closeEntry();
            }
        }
    }

    public static long getFolderSize(File folder) {
        long length = 0;
        File[] files = folder.listFiles();

        int count = files.length;

        for (int i = 0; i < count; i++) {
            if (files[i].isFile())
                length += files[i].length();
            else
                length += getFolderSize(files[i]);
        }

        return length;
    }

    private static void zipSingleFile(File file, File zipFile) throws IOException {
        try (ZipOutputStream zos = new ZipOutputStream(new FileOutputStream(zipFile));
                FileInputStream fis = new FileInputStream(file);) {
            ZipEntry ze = new ZipEntry(file.getName());

            zos.putNextEntry(ze);

            byte[] buffer = new byte[1024];

            int len;
            while ((len = fis.read(buffer)) > 0) {
                zos.write(buffer, 0, len);
            }

            zos.closeEntry();
        }
    }

    public static void zipFile(File file, File zipFile) throws IOException {
        if (file.isDirectory())
            zipDirectory(file, zipFile);
        else
            zipSingleFile(file, zipFile);
    }
}