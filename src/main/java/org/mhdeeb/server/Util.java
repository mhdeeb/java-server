package org.mhdeeb.server;

import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.URI;
import java.net.URL;
import java.net.URLConnection;

interface ByteTransformer<T> {
    public T transform(byte c);
}

public class Util {
    @SuppressWarnings("unused")
    public static void printAll(BufferedInputStream in) throws IOException {
        char c;
        while ((c = (char) in.read()) != -1) {
            System.out.print(c);
        }
    }

    public static String getIPLookUp(String ip) {
        try {
            URI uri = new URI("https://ipapi.co/" + ip + "/json/");

            URL api = uri.toURL();

            URLConnection yc = api.openConnection();
            BufferedReader in = new BufferedReader(
                    new InputStreamReader(
                            yc.getInputStream()));

            String inputLine;
            String text = "";

            while ((inputLine = in.readLine()) != null)
                text += inputLine + "\n";

            in.close();

            return (text.split("\"country_name\": \"")[1]).split("\"")[0].trim() + " ("
                    + (text.split("\"org\": \"")[1]).split("\"")[0].trim() + ")";
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