package com.xssscan.util;

public class ScanResult {

    private final String url;
    private final String displayUrl;
    private final byte[] rawRequest;
    private final byte[] rawResponse;
    private final String highlightedReq;
    private final String highlightedResp;
    private final Object httpService;

    public ScanResult(String url, String displayUrl, byte[] rawRequest, byte[] rawResponse,
                      String highlightedReq, String highlightedResp, Object httpService) {
        this.url = url;
        this.displayUrl = displayUrl;
        this.rawRequest = rawRequest;
        this.rawResponse = rawResponse;
        this.highlightedReq = highlightedReq;
        this.highlightedResp = highlightedResp;
        this.httpService = httpService;
    }

    public String getUrl() { return url; }
    public String getDisplayUrl() { return displayUrl; }
    public byte[] getRawRequest() { return rawRequest; }
    public byte[] getRawResponse() { return rawResponse; }
    public String getHighlightedReq() { return highlightedReq; }
    public String getHighlightedResp() { return highlightedResp; }
    public Object getHttpService() { return httpService; }
}
