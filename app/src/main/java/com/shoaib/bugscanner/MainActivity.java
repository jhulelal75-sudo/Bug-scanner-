package com.shoaib.bugscanner;

import android.app.Activity;
import android.os.Bundle;
import android.graphics.Color;
import android.view.Gravity;
import android.view.ViewGroup;
import android.widget.*;
import android.text.InputType;

import java.net.*;
import java.io.*;
import java.security.cert.X509Certificate;
import javax.net.ssl.HttpsURLConnection;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;

public class MainActivity extends Activity {

    LinearLayout layout;
    EditText domainInput;
    TextView results;
    Button scanButton;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        ScrollView scroll = new ScrollView(this);

        layout = new LinearLayout(this);
        layout.setOrientation(LinearLayout.VERTICAL);
        layout.setPadding(24, 30, 24, 30);
        layout.setBackgroundColor(Color.rgb(15, 23, 42));

        TextView title = new TextView(this);
        title.setText("SHOAIB BUG SCANNER");
        title.setTextSize(25);
        title.setTextColor(Color.WHITE);
        title.setGravity(Gravity.CENTER);
        layout.addView(title);

        TextView subtitle = new TextView(this);
        subtitle.setText("REAL WEBSITE SECURITY CHECKER");
        subtitle.setTextSize(14);
        subtitle.setTextColor(Color.LTGRAY);
        subtitle.setGravity(Gravity.CENTER);
        layout.addView(subtitle);

        domainInput = new EditText(this);
        domainInput.setHint("example.com");
        domainInput.setSingleLine(true);
        domainInput.setTextColor(Color.BLACK);
        domainInput.setHintTextColor(Color.GRAY);
        domainInput.setBackgroundColor(Color.WHITE);
        domainInput.setInputType(InputType.TYPE_TEXT_VARIATION_URI);

        LinearLayout.LayoutParams params =
            new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, 60);
        params.topMargin = 30;
        layout.addView(domainInput, params);

        scanButton = new Button(this);
        scanButton.setText("START SECURITY CHECK");
        layout.addView(scanButton);

        results = new TextView(this);
        results.setTextColor(Color.WHITE);
        results.setTextSize(15);
        results.setPadding(5, 25, 5, 20);
        layout.addView(results);

        scroll.addView(layout);
        setContentView(scroll);

        scanButton.setOnClickListener(v -> startScan());
    }

    private void startScan() {

        String domain = domainInput.getText().toString()
            .trim().toLowerCase(Locale.US);

        if (domain.startsWith("https://"))
            domain = domain.substring(8);

        if (domain.startsWith("http://"))
            domain = domain.substring(7);

        if (domain.contains("/") || domain.contains(":")
                || domain.contains(" ") || domain.isEmpty()) {
            domainInput.setError("Enter a valid domain only");
            return;
        }

        final String host;

        try {
            host = IDN.toASCII(domain);
            if (!host.matches(
                "(?i)[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?")) {
                throw new Exception("Invalid domain");
            }
        } catch (Exception e) {
            domainInput.setError("Invalid domain");
            return;
        }

        scanButton.setEnabled(false);
        results.setText("SCANNING...\nPlease wait.");

        new Thread(() -> {

            StringBuilder report = new StringBuilder();

            report.append("SHOAIB BUG SCANNER\n");
            report.append("========================\n");
            report.append("Domain: ").append(host).append("\n\n");

            // DNS LOOKUP
            report.append("[1] DNS LOOKUP\n");

            try {
                InetAddress[] addresses =
                    InetAddress.getAllByName(host);

                for (InetAddress address : addresses) {
                    report.append("IP: ")
                        .append(address.getHostAddress())
                        .append("\n");
                }

                report.append("DNS: SUCCESS\n");

            } catch (Exception e) {
                report.append("DNS: FAILED - ")
                    .append(e.getMessage()).append("\n");
            }

            // HTTPS CHECK AND SSL CERTIFICATE
            report.append("\n[2] HTTPS / HTTP STATUS\n");

            HttpsURLConnection connection = null;

            try {
                URL url = new URL("https://" + host);
                connection =
                    (HttpsURLConnection) url.openConnection();

                connection.setRequestMethod("GET");
                connection.setConnectTimeout(10000);
                connection.setReadTimeout(10000);
                connection.setInstanceFollowRedirects(true);
                connection.setRequestProperty(
                    "User-Agent", "ShoaibBugScanner/1.0");
                connection.setRequestProperty("Range", "bytes=0-0");

                int status = connection.getResponseCode();

                report.append("HTTP STATUS: ")
                    .append(status).append("\n");

                report.append("FINAL URL: ")
                    .append(connection.getURL()).append("\n");

                report.append("HTTPS: CONNECTED\n");

                // SSL CERTIFICATE
                report.append("\n[3] SSL CERTIFICATE\n");

                try {
                    java.security.cert.Certificate[] certs =
                        connection.getServerCertificates();

                    X509Certificate cert =
                        (X509Certificate) certs[0];

                    cert.checkValidity();

                    SimpleDateFormat sdf =
                        new SimpleDateFormat(
                            "yyyy-MM-dd", Locale.US);

                    report.append("Certificate: VALID\n");
                    report.append("Issued To: ")
                        .append(cert.getSubjectX500Principal())
                        .append("\n");

                    report.append("Expires: ")
                        .append(sdf.format(cert.getNotAfter()))
                        .append("\n");

                    long days =
                        (cert.getNotAfter().getTime()
                        - System.currentTimeMillis())
                        / 86400000L;

                    report.append("Days Remaining: ")
                        .append(days).append("\n");

                } catch (Exception e) {
                    report.append("SSL WARNING: ")
                        .append(e.getMessage()).append("\n");
                }

                // SECURITY HEADERS
                report.append("\n[4] SECURITY HEADERS\n");

                String[] headers = {
                    "Strict-Transport-Security",
                    "Content-Security-Policy",
                    "X-Content-Type-Options",
                    "X-Frame-Options",
                    "Referrer-Policy",
                    "Permissions-Policy"
                };

                for (String header : headers) {
                    String value =
                        connection.getHeaderField(header);

                    report.append(header).append(": ");

                    if (value != null && !value.isEmpty()) {
                        report.append("PRESENT\n");
                    } else {
                        report.append("MISSING\n");
                    }
                }

            } catch (Exception e) {
                report.append("HTTPS CHECK FAILED: ")
                    .append(e.getMessage()).append("\n");
            } finally {
                if (connection != null)
                    connection.disconnect();
            }

            // COMMON TCP PORT CHECK
            report.append("\n[5] TCP PORT CHECK\n");

            int[] ports = {80, 443, 8080, 8443};

            for (int port : ports) {

                try (Socket socket = new Socket()) {

                    socket.connect(
                        new InetSocketAddress(host, port), 2500);

                    report.append("Port ")
                        .append(port).append(": OPEN\n");

                } catch (Exception e) {

                    report.append("Port ")
                        .append(port).append(": CLOSED / FILTERED / UNREACHABLE\n");
                }
            }

            report.append("\n========================\n");
            report.append("SCAN FINISHED\n");
            report.append("For authorized testing only.\n");
            report.append("Missing headers are observations, not proof of a vulnerability.");

            final String finalReport = report.toString();

            runOnUiThread(() -> {
                results.setText(finalReport);
                scanButton.setEnabled(true);
            });

        }).start();
    }
}
