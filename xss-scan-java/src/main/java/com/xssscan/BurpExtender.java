package com.xssscan;

import burp.*;

import com.xssscan.ui.MainPanel;
import com.xssscan.util.UrlHashUtil;

import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

public class BurpExtender implements IBurpExtender, IHttpListener, ITab {

    private static final Set<String> EXCLUDED_EXTENSIONS = ConcurrentHashMap.newKeySet();
    private static final Set<Integer> EXCLUDED_STATUS_CODES = ConcurrentHashMap.newKeySet();

    private static final String[] ERROR_FIELDS = {
        "error", "errors", "errmsg", "error_msg", "error_message",
        "message", "msg", "description", "detail", "details",
        "reason", "exception", "cause", "trace", "stacktrace",
        "fail_msg", "failure", "fault", "warning", "alert"
    };

    static {
        String[] exts = {
            ".3g2", ".3gp", ".7z", ".aac", ".abw", ".aif", ".aifc", ".aiff",
            ".arc", ".au", ".avi", ".azw", ".bin", ".bmp", ".bz", ".bz2",
            ".cmx", ".cod", ".csh", ".css", ".csv", ".doc", ".docx", ".eot",
            ".epub", ".gif", ".gz", ".ico", ".ics", ".ief", ".jar", ".jfif",
            ".jpe", ".jpeg", ".jpg", ".m3u", ".mid", ".midi", ".mjs", ".mp2",
            ".mp3", ".mpa", ".mpe", ".mpeg", ".mpg", ".mpkg", ".mpp", ".mpv2",
            ".odp", ".ods", ".odt", ".oga", ".ogv", ".ogx", ".otf", ".pbm",
            ".pdf", ".pgm", ".png", ".pnm", ".ppm", ".ppt", ".pptx", ".ra",
            ".ram", ".rar", ".ras", ".rgb", ".rmi", ".rtf", ".snd", ".svg",
            ".swf", ".tar", ".tif", ".tiff", ".ttf", ".vsd", ".wav", ".weba",
            ".webm", ".webp", ".woff", ".woff2", ".xbm", ".xls", ".xlsx",
            ".xpm", ".xul", ".xwd", ".zip", ".js"
        };
        for (String ext : exts) EXCLUDED_EXTENSIONS.add(ext);
        EXCLUDED_STATUS_CODES.add(404);
        EXCLUDED_STATUS_CODES.add(502);
        EXCLUDED_STATUS_CODES.add(503);
    }

    public static final String PAYLOAD_HTML = "<h1>sunday0w0</h1>";
    public static final String PAYLOAD_HTML_ENCODED = "%3Ch1%3Esunday0w0%3C%2Fh1%3E";
    public static final String PAYLOAD_ALTERNATIVE = "sundayY0w0Y";

    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private PrintWriter stdout;

    private volatile boolean enabled = true;
    private volatile String[] excludedDomains = new String[0];

    private final Set<String> seenUrls = ConcurrentHashMap.newKeySet();
    private final ConcurrentHashMap<String, String> scanHistory = new ConcurrentHashMap<>();

    private volatile ExecutorService executor;

    private MainPanel mainPanel;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        this.stdout = new PrintWriter(callbacks.getStdout(), true);

        callbacks.setExtensionName("XSS-Scan");
        callbacks.registerHttpListener(this);

        executor = new ThreadPoolExecutor(10, 20, 30, TimeUnit.SECONDS,
                new LinkedBlockingQueue<>(100));

        mainPanel = new MainPanel(this);

        callbacks.addSuiteTab(this);

        stdout.println("[+] XSS-Scan plugin loaded");
        stdout.println("[+] Author: SunDay2__");
    }

    public IBurpExtenderCallbacks getCallbacks() { return callbacks; }
    public IExtensionHelpers getHelpers() { return helpers; }
    public PrintWriter getStdout() { return stdout; }
    public boolean isEnabled() { return enabled; }
    public void setEnabled(boolean v) { this.enabled = v; }
    public MainPanel getMainPanel() { return mainPanel; }

    public void setWhitelist(String text) {
        if (text == null || text.trim().isEmpty()) {
            this.excludedDomains = new String[0];
            stdout.println("[+] 白名单已清除");
            return;
        }
        String[] parts = text.trim().split(",");
        java.util.List<String> cleaned = new ArrayList<>();
        for (String p : parts) {
            String d = p.trim().toLowerCase();
            if (!d.isEmpty()) cleaned.add(d);
        }
        this.excludedDomains = cleaned.toArray(new String[0]);
        stdout.println("[+] 白名单已更新, 排除域名: " + String.join(", ", this.excludedDomains));
    }

    public void setThreadCount(int n) {
        if (n < 1 || n > 100) {
            stdout.println("[-] 线程数必须在 1-100 之间");
            return;
        }
        ExecutorService old = this.executor;
        this.executor = new ThreadPoolExecutor(n, n, 30, TimeUnit.SECONDS,
                new LinkedBlockingQueue<>(100));
        old.shutdown();
        try {
            if (!old.awaitTermination(5, TimeUnit.SECONDS)) {
                old.shutdownNow();
            }
        } catch (InterruptedException ignored) {}
        stdout.println("[+] 线程数已更新: " + n);
    }

    public void clearAll() {
        seenUrls.clear();
        scanHistory.clear();
        mainPanel.clearResults();
    }

    // --- HTTP Listener ---
    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        if (!enabled || !messageIsRequest || toolFlag != callbacks.TOOL_PROXY) return;

        try {
            IHttpService svc = messageInfo.getHttpService();
            String host = svc.getHost();
            if (isDomainExcluded(host)) return;

            byte[] req = messageInfo.getRequest();
            IRequestInfo info = helpers.analyzeRequest(svc, req);
            String url = info.getUrl().toString();

            String urlHash = UrlHashUtil.getUrlHash(url);
            if (!seenUrls.add(urlHash)) return;

            scanHistory.put(urlHash, url);

            String path = info.getUrl().getPath().toLowerCase();
            for (String ext : EXCLUDED_EXTENSIONS) {
                if (path.endsWith(ext)) return;
            }

            final String hash = urlHash;
            executor.submit(() -> scan(svc, req, hash));
        } catch (Exception e) {
            stdout.println("[-] processHttpMessage error: " + e.getMessage());
        }
    }

    private boolean isDomainExcluded(String host) {
        String lower = host.toLowerCase();
        for (String domain : excludedDomains) {
            if (domain.startsWith("*.")) {
                String suffix = domain.substring(1);
                if (lower.endsWith(suffix) || lower.equals(domain.substring(2))) return true;
            } else {
                if (lower.equals(domain) || lower.endsWith("." + domain)) return true;
            }
        }
        return false;
    }

    private void scan(IHttpService svc, byte[] origReq, String urlHash) {
        try {
            IRequestInfo info = helpers.analyzeRequest(svc, origReq);
            java.util.List<IParameter> params = info.getParameters();

            for (IParameter p : params) {
                // Payload 1: HTML标签检测
                IParameter p1 = helpers.buildParameter(p.getName(), PAYLOAD_HTML_ENCODED, p.getType());
                byte[] req1 = helpers.updateParameter(origReq, p1);
                IHttpRequestResponse resp1 = callbacks.makeHttpRequest(svc, req1);

                int status1 = getStatusCode(resp1.getResponse());
                if (EXCLUDED_STATUS_CODES.contains(status1) || status1 != 200) continue;

                String body1 = helpers.bytesToString(resp1.getResponse());

                if (isJsonErrorFalsePositive(resp1.getResponse(), PAYLOAD_HTML)) continue;

                if (body1.contains(PAYLOAD_HTML)) {
                    String displayUrl = scanHistory.getOrDefault(urlHash, urlHash);
                    javax.swing.SwingUtilities.invokeLater(() ->
                        mainPanel.addResult(1, displayUrl, req1, resp1.getResponse(), svc)
                    );
                    return;
                }

                // Payload 2: 纯文本反射检测
                IParameter p2 = helpers.buildParameter(p.getName(), PAYLOAD_ALTERNATIVE, p.getType());
                byte[] req2 = helpers.updateParameter(origReq, p2);
                IHttpRequestResponse resp2 = callbacks.makeHttpRequest(svc, req2);

                int status2 = getStatusCode(resp2.getResponse());
                if (EXCLUDED_STATUS_CODES.contains(status2) || status2 != 200) continue;

                String body2 = helpers.bytesToString(resp2.getResponse());

                if (isJsonErrorFalsePositive(resp2.getResponse(), PAYLOAD_ALTERNATIVE)) continue;

                if (body2.contains(PAYLOAD_ALTERNATIVE)) {
                    String displayUrl = scanHistory.getOrDefault(urlHash, urlHash);
                    javax.swing.SwingUtilities.invokeLater(() ->
                        mainPanel.addResult(2, displayUrl, req2, resp2.getResponse(), svc)
                    );
                    return;
                }
            }
        } catch (Exception e) {
            stdout.println("[-] scan error: " + e.getMessage());
        }
    }

    private int getStatusCode(byte[] response) {
        if (response == null) return 0;
        IResponseInfo info = helpers.analyzeResponse(response);
        return info.getStatusCode();
    }

    private boolean isJsonResponse(byte[] response) {
        if (response == null) return false;
        IResponseInfo info = helpers.analyzeResponse(response);
        for (String header : info.getHeaders()) {
            if (header.toLowerCase().startsWith("content-type:")) {
                return header.toLowerCase().contains("application/json");
            }
        }
        int bodyOffset = info.getBodyOffset();
        if (bodyOffset < response.length) {
            byte[] bodyBytes = new byte[Math.min(2048, response.length - bodyOffset)];
            System.arraycopy(response, bodyOffset, bodyBytes, 0, bodyBytes.length);
            String body = new String(bodyBytes).trim();
            return (body.startsWith("{") && body.endsWith("}")) ||
                   (body.startsWith("[") && body.endsWith("]"));
        }
        return false;
    }

    private boolean isJsonErrorFalsePositive(byte[] response, String payload) {
        if (!isJsonResponse(response)) return false;

        IResponseInfo respInfo = helpers.analyzeResponse(response);
        int bodyOffset = respInfo.getBodyOffset();
        if (bodyOffset >= response.length) return false;
        String body = new String(response, bodyOffset, response.length - bodyOffset);

        if (!body.contains(payload)) return false;

        List<String> errorValues = new ArrayList<>();
        for (String field : ERROR_FIELDS) {
            collectFieldValues(body, field, errorValues);
        }

        if (errorValues.isEmpty()) return false;

        int total = countOccurrences(body, payload);
        int inError = 0;
        for (String val : errorValues) {
            inError += countOccurrences(val, payload);
        }

        return total > 0 && total <= inError;
    }

    private void collectFieldValues(String json, String fieldName, List<String> results) {
        String lower = json.toLowerCase();
        String target = "\"" + fieldName + "\"";
        int pos = 0;

        while ((pos = lower.indexOf(target, pos)) >= 0) {
            int afterKey = pos + target.length();
            int colonPos = skipWs(json, afterKey);

            if (colonPos < json.length() && json.charAt(colonPos) == ':') {
                int valueStart = skipWs(json, colonPos + 1);
                if (valueStart < json.length()) {
                    String value = extractJsonValue(json, valueStart);
                    if (value != null) {
                        results.add(value);
                    }
                }
            }

            pos = afterKey;
        }
    }

    private int skipWs(String s, int pos) {
        while (pos < s.length() && Character.isWhitespace(s.charAt(pos))) pos++;
        return pos;
    }

    private String extractJsonValue(String json, int start) {
        if (start >= json.length()) return null;

        char c = json.charAt(start);

        if (c == '"') {
            int end = start + 1;
            while (end < json.length()) {
                if (json.charAt(end) == '\\') { end += 2; continue; }
                if (json.charAt(end) == '"') break;
                end++;
            }
            if (end < json.length()) {
                return json.substring(start + 1, end);
            }
        } else if (c == '{' || c == '[') {
            return extractBalanced(json, start);
        } else {
            int end = start;
            while (end < json.length() && ",}] \n\r\t".indexOf(json.charAt(end)) < 0) {
                end++;
            }
            if (end > start) {
                return json.substring(start, end);
            }
        }

        return null;
    }

    private int countOccurrences(String text, String sub) {
        int count = 0;
        int pos = 0;
        while ((pos = text.indexOf(sub, pos)) >= 0) {
            count++;
            pos += sub.length();
        }
        return count;
    }

    private String extractBalanced(String s, int start) {
        char open = s.charAt(start);
        char close = (open == '{') ? '}' : ']';
        int depth = 0;
        int end = start;
        while (end < s.length()) {
            char c = s.charAt(end);
            if (c == '"') {
                end++;
                while (end < s.length()) {
                    if (s.charAt(end) == '\\') { end += 2; continue; }
                    if (s.charAt(end) == '"') break;
                    end++;
                }
            } else if (c == open) {
                depth++;
            } else if (c == close) {
                depth--;
                if (depth == 0) break;
            }
            end++;
        }
        return s.substring(start, Math.min(end + 1, s.length()));
    }

    @Override
    public String getTabCaption() { return "XSS-Scan"; }

    @Override
    public java.awt.Component getUiComponent() { return mainPanel; }
}
