package com.xssscan.util;

import java.net.URL;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class UrlHashUtil {

    public static String getUrlHash(String urlStr) {
        try {
            URL url = new URL(urlStr);
            String path = url.getPath();
            String query = url.getQuery();

            String pathHash = md5(path);
            String paramHash = "";

            if (query != null && !query.isEmpty()) {
                List<String> paramNames = new ArrayList<>();
                for (String param : query.split("&")) {
                    int eqIdx = param.indexOf('=');
                    if (eqIdx > 0) {
                        paramNames.add(param.substring(0, eqIdx));
                    } else {
                        paramNames.add(param);
                    }
                }
                Collections.sort(paramNames);
                paramHash = md5(String.join("&", paramNames));
            }

            return pathHash + "_" + paramHash;
        } catch (Exception e) {
            return md5(urlStr);
        }
    }

    private static String md5(String input) {
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] digest = md.digest(input.getBytes("UTF-8"));
            StringBuilder sb = new StringBuilder();
            for (byte b : digest) {
                sb.append(String.format("%02x", b & 0xff));
            }
            return sb.toString();
        } catch (NoSuchAlgorithmException e) {
            return String.valueOf(input.hashCode());
        } catch (Exception e) {
            return String.valueOf(input.hashCode());
        }
    }
}
