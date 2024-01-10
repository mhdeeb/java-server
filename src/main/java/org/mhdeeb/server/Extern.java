package org.mhdeeb.server;

import java.io.File;
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;

public class Extern {
    public static List<String> getBlackList() {

        File file = new File(System.getenv("JSERVER_BLACK_LIST"));

        ArrayList<String> blackList = new ArrayList<>();

        try (Scanner fileReader = new Scanner(file)) {
            while (fileReader.hasNextLine()) {
                blackList.add(fileReader.nextLine());
            }
            return blackList;
        } catch (Exception e) {
            return blackList;
        }
    }

    public static String getPassword() {
        return System.getenv("JSERVER_CERT_PASSWORD");
    }

    public static File getIPLookupFile() {
        return new File(System.getenv("JSERVER_IP_LOOKUP"));
    }
}
