package com.xssscan.ui;

import burp.IHttpService;

import com.xssscan.BurpExtender;
import com.xssscan.util.ClipboardUtil;
import com.xssscan.util.ScanResult;

import javax.swing.*;
import javax.swing.border.TitledBorder;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;
import java.awt.*;
import java.awt.event.*;
import java.net.URL;
import java.util.concurrent.ConcurrentHashMap;

public class MainPanel extends JPanel {

    private final BurpExtender extender;

    private final DefaultListModel<String> model1 = new DefaultListModel<>();
    private final DefaultListModel<String> model2 = new DefaultListModel<>();
    private final JList<String> list1 = new JList<>(model1);
    private final JList<String> list2 = new JList<>(model2);

    private final JEditorPane reqArea = new JEditorPane("text/html", "");
    private final JEditorPane resArea = new JEditorPane("text/html", "");

    private final ConcurrentHashMap<String, ScanResult> resultMap = new ConcurrentHashMap<>();
    private volatile ScanResult currentResult;

    // Colors
    private static final Color COLOR_BG = new Color(245, 245, 245);
    private static final Color COLOR_SETTINGS_BG = new Color(240, 240, 240);
    private static final Color COLOR_CARD = Color.WHITE;
    private static final Color COLOR_BLUE = new Color(52, 119, 235);
    private static final Color COLOR_PURPLE = new Color(128, 0, 128);
    private static final Color COLOR_GREEN = new Color(46, 164, 79);
    private static final Color COLOR_RED = new Color(220, 53, 69);
    private static final Color COLOR_DARK = new Color(50, 50, 50);
    private static final Color COLOR_BORDER = new Color(200, 200, 200);
    private static final Color COLOR_BTN_HOVER = new Color(230, 230, 230);
    private static final Color COLOR_ACCENT = new Color(0, 122, 204);
    private static final Color COLOR_LABEL_GRAY = new Color(120, 120, 120);

    // Fonts
    private static final Font FONT_TITLE = new Font("Microsoft YaHei", Font.BOLD, 13);
    private static final Font FONT_LABEL = new Font("Microsoft YaHei", Font.PLAIN, 12);
    private static final Font FONT_BOLD = new Font("Microsoft YaHei", Font.BOLD, 12);
    private static final Font FONT_MONO = new Font("Monospaced", Font.PLAIN, 12);
    private static final Font FONT_ITA = new Font("Microsoft YaHei", Font.ITALIC, 11);
    private static final Font FONT_SECTION = new Font("Microsoft YaHei", Font.BOLD, 14);
    private static final Font FONT_HINT = new Font("Microsoft YaHei", Font.PLAIN, 11);

    // Toggle button
    private JButton toggleBtn;

    // Settings fields (need to persist for state readback)
    private JTextField wlField;
    private JTextField thField;
    private JLabel threadStatus;

    public MainPanel(BurpExtender extender) {
        this.extender = extender;
        setLayout(new BorderLayout());
        setBackground(COLOR_BG);

        JTabbedPane tabbedPane = new JTabbedPane(JTabbedPane.TOP);
        tabbedPane.setFont(FONT_BOLD);
        tabbedPane.setBackground(COLOR_BG);
        tabbedPane.setFocusable(false);

        tabbedPane.addTab("扫描", buildScanTab());
        tabbedPane.addTab("设置", buildSettingsTab());

        add(tabbedPane, BorderLayout.CENTER);
    }

    // ==================== 扫描页 ====================

    private JPanel buildScanTab() {
        JPanel panel = new JPanel(new BorderLayout(8, 8));
        panel.setBackground(COLOR_BG);
        panel.setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8));

        // Top bar: only toggle + clear
        panel.add(buildScanTopBar(), BorderLayout.NORTH);

        // Center: 2x2 split pane layout
        JSplitPane topSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT,
                buildListPanel("存在XSS", COLOR_BLUE, list1, model1, 1),
                buildListPanel("疑存 — 需人工判断", COLOR_PURPLE, list2, model2, 2));
        topSplit.setResizeWeight(0.5);
        topSplit.setDividerSize(4);

        JSplitPane reqSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT,
                buildDetailPanel("请求详情", reqArea),
                buildDetailPanel("响应详情", resArea));
        reqSplit.setResizeWeight(0.5);
        reqSplit.setDividerSize(4);

        JSplitPane mainSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT, topSplit, reqSplit);
        mainSplit.setResizeWeight(0.5);
        mainSplit.setDividerSize(4);

        panel.add(mainSplit, BorderLayout.CENTER);
        return panel;
    }

    private JPanel buildScanTopBar() {
        JPanel bar = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 6));
        bar.setBackground(COLOR_BG);

        toggleBtn = createStyledButton("已开启", COLOR_GREEN, Color.WHITE);
        toggleBtn.addActionListener(e -> {
            extender.setEnabled(!extender.isEnabled());
            if (extender.isEnabled()) {
                toggleBtn.setText("已开启");
                toggleBtn.setBackground(COLOR_GREEN);
            } else {
                toggleBtn.setText("已关闭");
                toggleBtn.setBackground(COLOR_RED);
            }
        });
        bar.add(toggleBtn);

        JButton clearBtn = createStyledButton("清空", Color.WHITE, COLOR_DARK);
        clearBtn.addActionListener(e -> extender.clearAll());
        bar.add(clearBtn);

        bar.add(createSpacer(20));

        JLabel authorLabel = new JLabel("作者 WX: SunDay2__");
        authorLabel.setFont(FONT_ITA);
        authorLabel.setForeground(Color.GRAY);
        bar.add(authorLabel);

        return bar;
    }

    // ==================== 设置页 ====================

    private JPanel buildSettingsTab() {
        JPanel outer = new JPanel(new BorderLayout());
        outer.setBackground(COLOR_SETTINGS_BG);

        JPanel content = new JPanel();
        content.setLayout(new BoxLayout(content, BoxLayout.Y_AXIS));
        content.setBackground(COLOR_SETTINGS_BG);
        content.setBorder(BorderFactory.createEmptyBorder(16, 16, 16, 16));

        content.add(buildWhitelistCard());
        content.add(Box.createVerticalStrut(12));
        content.add(buildThreadCard());
        content.add(Box.createVerticalStrut(12));
        content.add(buildAboutCard());
        content.add(Box.createVerticalGlue());

        JScrollPane scroll = new JScrollPane(content);
        scroll.setBorder(BorderFactory.createEmptyBorder());
        scroll.getVerticalScrollBar().setUnitIncrement(16);
        outer.add(scroll, BorderLayout.CENTER);

        return outer;
    }

    private JPanel buildWhitelistCard() {
        JPanel card = createCard();

        JLabel title = new JLabel("白名单设置");
        title.setFont(FONT_SECTION);
        title.setForeground(COLOR_DARK);
        title.setAlignmentX(Component.LEFT_ALIGNMENT);
        card.add(title);
        card.add(Box.createVerticalStrut(6));

        JLabel hint = new JLabel("添加的域名及其子域名将被排除，不进行扫描。多个域名用逗号分隔。");
        hint.setFont(FONT_HINT);
        hint.setForeground(COLOR_LABEL_GRAY);
        hint.setAlignmentX(Component.LEFT_ALIGNMENT);
        card.add(hint);
        card.add(Box.createVerticalStrut(8));

        wlField = new JTextField();
        wlField.setFont(FONT_LABEL);
        wlField.setMaximumSize(new Dimension(Integer.MAX_VALUE, 32));
        wlField.setAlignmentX(Component.LEFT_ALIGNMENT);
        wlField.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(COLOR_BORDER, 1),
                BorderFactory.createEmptyBorder(4, 8, 4, 8)));
        card.add(wlField);
        card.add(Box.createVerticalStrut(8));

        JPanel btnRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
        btnRow.setBackground(Color.WHITE);
        btnRow.setAlignmentX(Component.LEFT_ALIGNMENT);

        JButton applyBtn = createAccentButton("应用");
        applyBtn.addActionListener(e -> extender.setWhitelist(wlField.getText()));
        btnRow.add(applyBtn);

        JButton clearBtn = createPlainButton("清除");
        clearBtn.addActionListener(e -> {
            wlField.setText("");
            extender.setWhitelist("");
        });
        btnRow.add(clearBtn);

        card.add(btnRow);
        return card;
    }

    private JPanel buildThreadCard() {
        JPanel card = createCard();

        JLabel title = new JLabel("线程设置");
        title.setFont(FONT_SECTION);
        title.setForeground(COLOR_DARK);
        title.setAlignmentX(Component.LEFT_ALIGNMENT);
        card.add(title);
        card.add(Box.createVerticalStrut(6));

        JLabel hint = new JLabel("设置并发扫描线程数（范围 1-100），默认 10。");
        hint.setFont(FONT_HINT);
        hint.setForeground(COLOR_LABEL_GRAY);
        hint.setAlignmentX(Component.LEFT_ALIGNMENT);
        card.add(hint);
        card.add(Box.createVerticalStrut(8));

        JPanel row = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
        row.setBackground(Color.WHITE);
        row.setAlignmentX(Component.LEFT_ALIGNMENT);

        thField = new JTextField("10", 6);
        thField.setFont(FONT_LABEL);
        thField.setPreferredSize(new Dimension(60, 32));
        thField.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(COLOR_BORDER, 1),
                BorderFactory.createEmptyBorder(4, 8, 4, 8)));
        row.add(thField);

        JButton setBtn = createAccentButton("设置");
        setBtn.addActionListener(e -> {
            try {
                int n = Integer.parseInt(thField.getText().trim());
                extender.setThreadCount(n);
                updateThreadStatus();
            } catch (NumberFormatException ex) {
                extender.getStdout().println("[-] 无效的线程数");
            }
        });
        row.add(setBtn);

        card.add(row);
        card.add(Box.createVerticalStrut(8));

        threadStatus = new JLabel("当前线程数: 10");
        threadStatus.setFont(FONT_HINT);
        threadStatus.setForeground(COLOR_LABEL_GRAY);
        threadStatus.setAlignmentX(Component.LEFT_ALIGNMENT);
        card.add(threadStatus);

        return card;
    }

    private JPanel buildAboutCard() {
        JPanel card = createCard();

        JLabel title = new JLabel("关于");
        title.setFont(FONT_SECTION);
        title.setForeground(COLOR_DARK);
        title.setAlignmentX(Component.LEFT_ALIGNMENT);
        card.add(title);
        card.add(Box.createVerticalStrut(6));

        JLabel info = new JLabel("XSS-Scan — 被动式 XSS 检测 Burp Suite 插件");
        info.setFont(FONT_LABEL);
        info.setForeground(COLOR_DARK);
        info.setAlignmentX(Component.LEFT_ALIGNMENT);
        card.add(info);
        card.add(Box.createVerticalStrut(4));

        JLabel author = new JLabel("作者 WX: SunDay2__");
        author.setFont(FONT_HINT);
        author.setForeground(COLOR_LABEL_GRAY);
        author.setAlignmentX(Component.LEFT_ALIGNMENT);
        card.add(author);

        return card;
    }

    private JPanel createCard() {
        JPanel card = new JPanel();
        card.setLayout(new BoxLayout(card, BoxLayout.Y_AXIS));
        card.setBackground(COLOR_CARD);
        card.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(new Color(220, 220, 220), 1),
                BorderFactory.createEmptyBorder(16, 16, 16, 16)));
        card.setAlignmentX(Component.LEFT_ALIGNMENT);
        return card;
    }

    private JButton createAccentButton(String text) {
        JButton btn = new JButton(text);
        btn.setFont(FONT_BOLD);
        btn.setBackground(COLOR_ACCENT);
        btn.setForeground(Color.WHITE);
        btn.setFocusPainted(false);
        btn.setBorder(BorderFactory.createEmptyBorder(6, 20, 6, 20));
        btn.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
        btn.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseEntered(MouseEvent e) {
                btn.setBackground(COLOR_ACCENT.darker());
            }
            @Override
            public void mouseExited(MouseEvent e) {
                btn.setBackground(COLOR_ACCENT);
            }
        });
        return btn;
    }

    private JButton createPlainButton(String text) {
        JButton btn = new JButton(text);
        btn.setFont(FONT_LABEL);
        btn.setBackground(Color.WHITE);
        btn.setForeground(COLOR_DARK);
        btn.setFocusPainted(false);
        btn.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(COLOR_BORDER, 1),
                BorderFactory.createEmptyBorder(5, 16, 5, 16)));
        btn.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
        btn.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseEntered(MouseEvent e) {
                btn.setBackground(COLOR_BTN_HOVER);
            }
            @Override
            public void mouseExited(MouseEvent e) {
                btn.setBackground(Color.WHITE);
            }
        });
        return btn;
    }

    private void updateThreadStatus() {
        try {
            int n = Integer.parseInt(thField.getText().trim());
            threadStatus.setText("当前线程数: " + n);
        } catch (NumberFormatException ignored) {
        }
    }

    // ==================== URL 列表面板 ====================

    private JPanel buildListPanel(String title, Color accentColor, JList<String> list,
                                   DefaultListModel<String> model, int listIdx) {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBackground(Color.WHITE);
        TitledBorder border = BorderFactory.createTitledBorder(
                BorderFactory.createLineBorder(accentColor, 2),
                title, TitledBorder.LEFT, TitledBorder.TOP, FONT_TITLE, accentColor);
        panel.setBorder(BorderFactory.createCompoundBorder(border,
                BorderFactory.createEmptyBorder(4, 4, 4, 4)));

        list.setFont(FONT_MONO);
        list.setFixedCellHeight(22);
        list.setSelectionBackground(accentColor);
        list.setSelectionForeground(Color.WHITE);
        list.setBackground(Color.WHITE);

        list.addListSelectionListener(new ListSelectionListener() {
            @Override
            public void valueChanged(ListSelectionEvent e) {
                if (e.getValueIsAdjusting()) return;
                String sel = list.getSelectedValue();
                if (sel == null) return;
                if (listIdx == 1) list2.clearSelection();
                else list1.clearSelection();
                showDetail(sel);
            }
        });

        // Right-click: only "复制URL链接"
        JPopupMenu popup = new JPopupMenu();
        popup.setFont(FONT_LABEL);
        popup.setBackground(Color.WHITE);

        JMenuItem copyUrl = new JMenuItem("复制URL链接");
        copyUrl.setFont(FONT_LABEL);
        copyUrl.addActionListener(e -> {
            String sel = list.getSelectedValue();
            if (sel != null) {
                ScanResult sr = resultMap.get(sel);
                ClipboardUtil.copy(sr != null ? sr.getUrl() : sel);
            }
        });
        popup.add(copyUrl);

        list.setComponentPopupMenu(popup);
        list.addMouseListener(new MouseAdapter() {
            @Override
            public void mousePressed(MouseEvent e) { checkPopup(e); }
            @Override
            public void mouseReleased(MouseEvent e) { checkPopup(e); }
            private void checkPopup(MouseEvent e) {
                if (e.isPopupTrigger()) {
                    int idx = list.locationToIndex(e.getPoint());
                    if (idx >= 0) {
                        list.setSelectedIndex(idx);
                        popup.show(list, e.getX(), e.getY());
                    }
                }
            }
        });

        JScrollPane scroll = new JScrollPane(list);
        scroll.setBorder(BorderFactory.createEmptyBorder());
        panel.add(scroll, BorderLayout.CENTER);
        return panel;
    }

    // ==================== 详情面板 ====================

    private JPanel buildDetailPanel(String title, JEditorPane area) {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBackground(Color.WHITE);
        TitledBorder border = BorderFactory.createTitledBorder(
                BorderFactory.createLineBorder(COLOR_BORDER, 1),
                title, TitledBorder.LEFT, TitledBorder.TOP, FONT_TITLE, COLOR_DARK);
        panel.setBorder(BorderFactory.createCompoundBorder(border,
                BorderFactory.createEmptyBorder(4, 4, 4, 4)));

        area.setEditable(false);
        area.setFont(FONT_MONO);
        area.setBackground(Color.WHITE);

        // Right-click: full menu
        JPopupMenu popup = new JPopupMenu();
        popup.setFont(FONT_LABEL);
        popup.setBackground(Color.WHITE);

        JMenuItem copyItem = new JMenuItem("复制");
        copyItem.setFont(FONT_LABEL);
        copyItem.addActionListener(e -> {
            String selected = area.getSelectedText();
            if (selected != null && !selected.isEmpty()) {
                ClipboardUtil.copy(selected);
            } else {
                ClipboardUtil.copy(area.getText());
            }
        });
        popup.add(copyItem);

        JMenuItem copyAll = new JMenuItem("复制全部");
        copyAll.setFont(FONT_LABEL);
        copyAll.addActionListener(e -> ClipboardUtil.copy(area.getText()));
        popup.add(copyAll);

        popup.addSeparator();

        JMenuItem copyUrl = new JMenuItem("复制 URL");
        copyUrl.setFont(FONT_LABEL);
        copyUrl.addActionListener(e -> {
            if (currentResult != null) {
                ClipboardUtil.copy(currentResult.getUrl());
            }
        });
        popup.add(copyUrl);

        JMenuItem copyReq = new JMenuItem("复制请求包");
        copyReq.setFont(FONT_LABEL);
        copyReq.addActionListener(e -> {
            if (currentResult != null && currentResult.getRawRequest() != null) {
                ClipboardUtil.copy(new String(currentResult.getRawRequest()));
            }
        });
        popup.add(copyReq);

        JMenuItem copyResp = new JMenuItem("复制响应包");
        copyResp.setFont(FONT_LABEL);
        copyResp.addActionListener(e -> {
            if (currentResult != null && currentResult.getRawResponse() != null) {
                ClipboardUtil.copy(new String(currentResult.getRawResponse()));
            }
        });
        popup.add(copyResp);

        popup.addSeparator();

        JMenuItem sendRepeater = new JMenuItem("发送到 Repeater");
        sendRepeater.setFont(FONT_LABEL);
        sendRepeater.addActionListener(e -> {
            if (currentResult != null && currentResult.getHttpService() != null && currentResult.getRawRequest() != null) {
                try {
                    IHttpService svc = (IHttpService) currentResult.getHttpService();
                    extender.getCallbacks().sendToRepeater(
                            svc.getHost(), svc.getPort(),
                            svc.getProtocol().equalsIgnoreCase("https"),
                            currentResult.getRawRequest(), "XSS-Scan");
                } catch (Exception ex) {
                    extender.getStdout().println("[-] 发送到 Repeater 失败: " + ex.getMessage());
                }
            }
        });
        popup.add(sendRepeater);

        area.setComponentPopupMenu(popup);

        JScrollPane scroll = new JScrollPane(area);
        scroll.setBorder(BorderFactory.createEmptyBorder());
        panel.add(scroll, BorderLayout.CENTER);
        return panel;
    }

    // ==================== 公共方法 ====================

    private int resultCounter = 0;

    public void addResult(int listNo, String url, byte[] rawRequest, byte[] rawResponse, IHttpService svc) {
        String displayUrl = truncateUrl(url);

        // Generate unique key to avoid collision when different URLs truncate to same displayUrl
        String key = displayUrl;
        int suffix = 1;
        while (resultMap.containsKey(key)) {
            suffix++;
            key = displayUrl + " (" + suffix + ")";
        }
        final String uniqueKey = key;

        DefaultListModel<String> model = (listNo == 1) ? model1 : model2;
        model.addElement(uniqueKey);

        String reqStr = new String(rawRequest);
        String respStr = new String(rawResponse);

        String highlightedReq = highlightPayload(reqStr,
                listNo == 1 ? BurpExtender.PAYLOAD_HTML_ENCODED : BurpExtender.PAYLOAD_ALTERNATIVE);
        String highlightedResp = highlightPayload(respStr,
                listNo == 1 ? BurpExtender.PAYLOAD_HTML : BurpExtender.PAYLOAD_ALTERNATIVE);

        ScanResult sr = new ScanResult(url, uniqueKey, rawRequest, rawResponse,
                highlightedReq, highlightedResp, svc);
        resultMap.put(uniqueKey, sr);

        if (model.size() == 1) {
            JList<String> list = (listNo == 1) ? list1 : list2;
            list.setSelectedIndex(0);
            showDetail(uniqueKey);
        }
    }

    public void clearResults() {
        model1.clear();
        model2.clear();
        reqArea.setText("");
        resArea.setText("");
        resultMap.clear();
        currentResult = null;
    }

    // ==================== 内部方法 ====================

    private void showDetail(String displayUrl) {
        ScanResult sr = resultMap.get(displayUrl);
        if (sr != null) {
            currentResult = sr;
            reqArea.setText(sr.getHighlightedReq());
            resArea.setText(sr.getHighlightedResp());
            reqArea.setCaretPosition(0);
            resArea.setCaretPosition(0);
        }
    }

    private String truncateUrl(String url) {
        try {
            URL u = new URL(url);
            String path = u.getPath();
            String query = u.getQuery();
            String tPath = path.length() > 80 ? path.substring(0, 80) + "..." : path;
            String result = u.getProtocol() + "://" + u.getHost() + tPath;
            if (query != null && !query.isEmpty()) {
                result += "?" + (query.length() > 40 ? query.substring(0, 40) + "..." : query);
            }
            return result;
        } catch (Exception e) {
            return url.length() > 120 ? url.substring(0, 120) + "..." : url;
        }
    }

    private String highlightPayload(String content, String payload) {
        String escaped = escapeHtml(content);
        String escapedPayload = escapeHtml(payload);
        String highlighted = escaped.replace(escapedPayload,
                "<span style='background-color:#FFCCCC;border:1px solid #FF0000;" +
                "padding:0 2px;font-weight:bold;color:#CC0000;'>" + escapedPayload + "</span>");

        return "<html><body style='font-family:Monospaced;font-size:12px;line-height:1.5;'>" +
                "<pre style='margin:0'>" + highlighted + "</pre></body></html>";
    }

    private String escapeHtml(String s) {
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                .replace("\"", "&quot;").replace("'", "&#39;");
    }

    private JButton createStyledButton(String text, Color bg, Color fg) {
        JButton btn = new JButton(text);
        btn.setFont(FONT_BOLD);
        btn.setBackground(bg);
        btn.setForeground(fg);
        btn.setFocusPainted(false);
        btn.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(COLOR_BORDER, 1),
                BorderFactory.createEmptyBorder(4, 12, 4, 12)));
        btn.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));

        Color originalBg = bg;
        btn.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseEntered(MouseEvent e) {
                if (btn == toggleBtn) return;
                btn.setBackground(COLOR_BTN_HOVER);
            }
            @Override
            public void mouseExited(MouseEvent e) {
                if (btn == toggleBtn) return;
                btn.setBackground(originalBg);
            }
        });
        return btn;
    }

    private JPanel createSpacer(int width) {
        JPanel spacer = new JPanel();
        spacer.setPreferredSize(new Dimension(width, 1));
        spacer.setOpaque(false);
        return spacer;
    }
}
