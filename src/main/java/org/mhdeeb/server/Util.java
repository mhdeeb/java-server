package org.mhdeeb.server;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.net.URI;
import java.net.URL;
import java.net.URLConnection;

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
}