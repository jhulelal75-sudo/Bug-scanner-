package com.shoaib.bugscanner;

import android.app.Activity;
import android.os.Bundle;
import android.graphics.Color;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.widget.*;

import java.net.*;
import java.io.*;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.concurrent.*;

import javax.net.ssl.HttpsURLConnection;

public class MainActivity extends Activity {

    int bg = Color.rgb(9, 15, 29);
    int card = Color.rgb(20, 30, 49);
    int accent = Color.rgb(0, 220, 170);
    int white = Color.WHITE;
    int muted = Color.rgb(155, 170, 190);

    LinearLayout root, reportCard;
    EditText input;
    TextView status, report, score;
    Button scan, copy;
    String lastReport = "";

    @Override
    public void onCreate(Bundle b) {
        super.onCreate(b);

        getWindow().setStatusBarColor(bg);
        getWindow().setNavigationBarColor(bg);

        ScrollView scroll = new ScrollView(this);
        scroll.setBackgroundColor(bg);

        root = new LinearLayout(this);
        root.setOrientation(1);
        root.setPadding(dp(20), dp(25), dp(20), dp(35));

        scroll.addView(root);
        setContentView(scroll);

        TextView logo = text("◈", 42, accent, true);
        logo.setGravity(Gravity.CENTER);
        root.addView(logo);

        TextView title = text("SHOAIB BUG SCANNER", 24, white, true);
        title.setGravity(Gravity.CENTER);
        root.addView(title);

        TextView sub = text("WEBSITE SECURITY INTELLIGENCE", 11, muted, true);
        sub.setGravity(Gravity.CENTER);
        add(sub, 5);

        TextView badge = text("●  SECURITY SCANNER  •  ONLINE", 12, accent, true);
        badge.setGravity(Gravity.CENTER);
        add(badge, 20);

        panel("TARGET WEBSITE");

        input = new EditText(this);
        input.setSingleLine(true);
        input.setTextColor(white);
        input.setHintTextColor(muted);
        input.setHint("Enter domain e.g. example.com");
        input.setTextSize(16);
        input.setPadding(dp(15), dp(12), dp(15), dp(12));
        input.setBackground(shape(card, 12, Color.rgb(50,65,85)));
        root.addView(input, params(-1, 55));

        scan = new Button(this);
        scan.setText("START FULL SECURITY SCAN");
        scan.setTextColor(bg);
        scan.setTextSize(14);
        scan.setTypeface(null, Typeface.BOLD);
        scan.setBackground(shape(accent, 12, accent));
        LinearLayout.LayoutParams sp = params(-1, 55);
        sp.topMargin = dp(14);
        root.addView(scan, sp);

        status = text("READY TO SCAN", 13, accent, true);
        status.setGravity(Gravity.CENTER);
        add(status, 18);

        panel("SCAN MODULES");

        String[] modules = {
            "01   DNS & IP LOOKUP",
            "02   LIVE / DEAD HOST DETECTION",
            "03   SSL CERTIFICATE INSPECTION",
            "04   SECURITY HEADERS ANALYSIS",
            "05   COMMON TCP PORT CHECKS",
            "06   DETAILED SECURITY REPORT"
        };

        for (String s : modules) {
            TextView item = text("✓   " + s, 13, white, true);
            item.setPadding(dp(14), dp(13), dp(10), dp(13));
            item.setBackground(shape(card, 10, card));
            LinearLayout.LayoutParams p = params(-1, -2);
            p.topMargin = dp(7);
            root.addView(item, p);
        }

        panel("SCAN SUMMARY");

        score = text("Not scanned yet", 20, accent, true);
        score.setGravity(Gravity.CENTER);
        add(score, 10);

        panel("DETAILED RESULTS");

        reportCard = new LinearLayout(this);
        reportCard.setOrientation(1);
        reportCard.setPadding(dp(14), dp(14), dp(14), dp(14));
        reportCard.setBackground(shape(card, 12, card));

        report = text("Your scan results will appear here.", 13, white, false);
        report.setTextIsSelectable(true);
        reportCard.addView(report);
        root.addView(reportCard, params(-1, -2));

        copy = new Button(this);
        copy.setText("COPY SECURITY REPORT");
        copy.setTextColor(white);
        copy.setBackground(shape(Color.rgb(43,60,85), 12, Color.rgb(43,60,85)));
        LinearLayout.LayoutParams cp = params(-1, 50);
        cp.topMargin = dp(12);
        root.addView(copy, cp);

        TextView footer = text(
            "SHOAIB SECURITY TOOLS\nFor authorized security testing only.",
            11, muted, false);
        footer.setGravity(Gravity.CENTER);
        add(footer, 25);

        scan.setOnClickListener(v -> startScan());

        copy.setOnClickListener(v -> {
            if (lastReport.isEmpty()) {
                toast("No report available");
                return;
            }

            ClipboardManager cm = (ClipboardManager)
                getSystemService(Context.CLIPBOARD_SERVICE);

            cm.setPrimaryClip(ClipData.newPlainText("Security Report", lastReport));
            toast("Report copied");
        });
    }

    void startScan() {
        String domain = input.getText().toString().trim()
            .toLowerCase(Locale.US);

        domain = domain.replaceFirst("^https?://", "");
        domain = domain.replaceFirst("/.*$", "");

        if (domain.isEmpty() || domain.contains(":") ||
            domain.contains(" ") || domain.length() > 253) {
            input.setError("Enter a valid domain only");
            return;
        }

        final String host;
        try {
            host = IDN.toASCII(domain);
            if (!host.matches("(?i)[a-z0-9.-]+") ||
                host.startsWith(".") || host.endsWith(".") ||
                host.contains("..")) {
                throw new Exception();
            }
        } catch (Exception e) {
            input.setError("Invalid domain");
            return;
        }

        scan.setEnabled(false);
        scan.setText("SCANNING...");
        status.setText("● SCANNING " + host);
        report.setText("Please wait...\nRunning security checks.");

        ExecutorService executor = Executors.newSingleThreadExecutor();

        executor.execute(() -> {
            StringBuilder r = new StringBuilder();
            int passed = 0;
            int total = 0;

            r.append("SHOAIB BUG SCANNER\n");
            r.append("==============================\n");
            r.append("Target: ").append(host).append("\n");
            r.append("Date: ").append(new Date()).append("\n");
            r.append("==============================\n");

            // DNS
            r.append("\n[1] DNS AND IP LOOKUP\n");
            boolean dnsOK = false;

            try {
                InetAddress[] ips = InetAddress.getAllByName(host);
                for (InetAddress ip : ips) {
                    r.append("IP: ").append(ip.getHostAddress()).append("\n");
                }
                r.append("DNS: SUCCESS\n");
                dnsOK = true;
            } catch (Exception e) {
                r.append("DNS FAILED: ").append(e.getMessage()).append("\n");
            }
            total++;
            if (dnsOK) passed++;

            // HOST AVAILABILITY
            r.append("\n[2] HOST AVAILABILITY\n");
            boolean live = false;

            try (Socket s = new Socket()) {
                s.connect(new InetSocketAddress(host, 443), 4000);
                live = true;
                r.append("HOST: REACHABLE\n");
            } catch (Exception e) {
                r.append("HTTPS PORT: UNREACHABLE\n");
            }

            total++;
            if (live) passed++;

            // HTTPS / SSL / HEADERS
            r.append("\n[3] HTTPS AND SSL CERTIFICATE\n");

            HttpsURLConnection conn = null;

            try {
                URL url = new URL("https://" + host);
                conn = (HttpsURLConnection) url.openConnection();
                conn.setConnectTimeout(8000);
                conn.setReadTimeout(8000);
                conn.setRequestMethod("GET");
                conn.setInstanceFollowRedirects(true);
                conn.setRequestProperty("User-Agent", "ShoaibBugScanner/2.0");
                conn.setRequestProperty("Range", "bytes=0-0");

                int code = conn.getResponseCode();

                r.append("HTTP STATUS: ").append(code).append("\n");
                r.append("FINAL URL: ").append(conn.getURL()).append("\n");
                r.append("HTTPS: CONNECTED\n");

                total++;
                passed++;

                r.append("\nSSL CERTIFICATE DETAILS\n");

                X509Certificate cert =
                    (X509Certificate) conn.getServerCertificates()[0];

                cert.checkValidity();

                SimpleDateFormat fmt =
                    new SimpleDateFormat("yyyy-MM-dd", Locale.US);

                long days = (cert.getNotAfter().getTime()
                    - System.currentTimeMillis()) / 86400000L;

                r.append("Status: VALID\n");
                r.append("Subject: ")
                    .append(cert.getSubjectX500Principal()).append("\n");
                r.append("Issuer: ")
                    .append(cert.getIssuerX500Principal()).append("\n");
                r.append("Valid From: ")
                    .append(fmt.format(cert.getNotBefore())).append("\n");
                r.append("Expires: ")
                    .append(fmt.format(cert.getNotAfter())).append("\n");
                r.append("Days Remaining: ").append(days).append("\n");

                total++;
                passed++;

                // HEADERS
                r.append("\n[4] SECURITY HEADERS ANALYSIS\n");

                String[] headers = {
                    "Strict-Transport-Security",
                    "Content-Security-Policy",
                    "X-Content-Type-Options",
                    "X-Frame-Options",
                    "Referrer-Policy",
                    "Permissions-Policy"
                };

                int present = 0;

                for (String h : headers) {
                    String value = conn.getHeaderField(h);

                    r.append("\n").append(h).append(":\n");

                    if (value != null && !value.trim().isEmpty()) {
                        r.append("PRESENT: ").append(value).append("\n");
                        present++;
                    } else {
                        r.append("MISSING\n");
                    }
                }

                r.append("\nHeaders present: ")
                    .append(present).append("/").append(headers.length).append("\n");

            } catch (Exception e) {
                r.append("HTTPS / SSL ERROR: ")
                    .append(e.getMessage()).append("\n");
            } finally {
                if (conn != null) conn.disconnect();
            }

            // PORTS
            r.append("\n[5] COMMON TCP PORT CHECKS\n");

            int[] ports = {80, 443, 8080, 8443};

            for (int port : ports) {
                try (Socket s = new Socket()) {
                    s.connect(new InetSocketAddress(host, port), 2500);
                    r.append("Port ").append(port).append(": OPEN\n");
                } catch (Exception e) {
                    r.append("Port ").append(port)
                        .append(": CLOSED / FILTERED / UNREACHABLE\n");
                }
            }

            r.append("\n==============================\n");
            r.append("SCAN COMPLETED\n");
            r.append("Successful basic checks: ")
                .append(passed).append("/").append(total).append("\n");
            r.append("\nIMPORTANT:\n");
            r.append("This is an observation report, not a penetration test.\n");
            r.append("Missing headers do not automatically mean vulnerability.\n");
            r.append("Port checks are limited to the listed TCP ports.\n");
            r.append("Use only on websites you own or are authorized to test.\n");

            String result = r.toString();
            final int success = passed;
            final int count = total;

            runOnUiThread(() -> {
                lastReport = result;
                report.setText(result);
                score.setText(success + " / " + count + " BASIC CHECKS PASSED");
                status.setText("● SCAN COMPLETED");
                scan.setText("SCAN AGAIN");
                scan.setEnabled(true);
            });
        });

        executor.shutdown();
    }

    void panel(String name) {
        TextView t = text(name, 13, accent, true);
        LinearLayout.LayoutParams p = params(-1, -2);
        p.topMargin = dp(23);
        p.bottomMargin = dp(9);
        root.addView(t, p);
    }

    void add(View v, int top) {
        LinearLayout.LayoutParams p = params(-1, -2);
        p.topMargin = dp(top);
        root.addView(v, p);
    }

    TextView text(String value, int size, int color, boolean bold) {
        TextView t = new TextView(this);
        t.setText(value);
        t.setTextSize(size);
        t.setTextColor(color);
        if (bold) t.setTypeface(null, Typeface.BOLD);
        return t;
    }

    GradientDrawable shape(int color, int radius, int stroke) {
        GradientDrawable d = new GradientDrawable();
        d.setColor(color);
        d.setCornerRadius(dp(radius));
        d.setStroke(dp(1), stroke);
        return d;
    }

    LinearLayout.LayoutParams params(int w, int h) {
        return new LinearLayout.LayoutParams(w, h);
    }

    int dp(int v) {
        return (int)(v * getResources().getDisplayMetrics().density + 0.5f);
    }

    void toast(String message) {
        Toast.makeText(this, message, Toast.LENGTH_SHORT).show();
    }
}
