package com.shoaib.bugscanner;

import android.app.Activity;
import android.os.Bundle;
import android.graphics.Color;
import android.view.Gravity;
import android.widget.*;
import android.text.InputType;
import android.view.ViewGroup;
import java.net.URL;
import javax.net.ssl.HttpsURLConnection;

public class MainActivity extends Activity {

    LinearLayout layout;
    EditText domainInput;
    TextView results;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        layout = new LinearLayout(this);
        layout.setOrientation(LinearLayout.VERTICAL);
        layout.setPadding(24, 30, 24, 24);
        layout.setBackgroundColor(Color.rgb(15, 23, 42));

        TextView title = new TextView(this);
        title.setText("SHOAIB BUG SCANNER");
        title.setTextSize(25);
        title.setTextColor(Color.WHITE);
        title.setGravity(Gravity.CENTER);
        layout.addView(title);

        TextView subtitle = new TextView(this);
        subtitle.setText("Website Security Checker");
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

        LinearLayout.LayoutParams inputParams =
            new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, 60);
        inputParams.topMargin = 35;
        layout.addView(domainInput, inputParams);

        Button scanButton = new Button(this);
        scanButton.setText("START SCAN");
        layout.addView(scanButton);

        results = new TextView(this);
        results.setTextColor(Color.WHITE);
        results.setTextSize(15);
        results.setPadding(5, 25, 5, 5);
        layout.addView(results);

        scanButton.setOnClickListener(v -> {
            String domain = domainInput.getText().toString().trim();

            if (domain.isEmpty()) {
                domainInput.setError("Enter a domain");
                return;
            }

            results.setText("Checking website...\n" + domain);
            scanButton.setEnabled(false);

            new Thread(() -> {
                String output;

                try {
                    if (domain.contains("://") ||
                        domain.contains("/") ||
                        domain.contains(" ")) {
                        throw new Exception("Enter only a domain name.");
                    }

                    URL url = new URL("https://" + domain);
                    HttpsURLConnection connection =
                        (HttpsURLConnection) url.openConnection();

                    connection.setRequestMethod("HEAD");
                    connection.setConnectTimeout(8000);
                    connection.setReadTimeout(8000);

                    int code = connection.getResponseCode();

                    output = "SCAN COMPLETE\n\n"
                        + "Domain: " + domain + "\n"
                        + "HTTPS Status: " + code + "\n"
                        + "HTTPS Connection: Successful\n\n"
                        + "Note: This is a basic connectivity check, "
                        + "not a vulnerability scan.";

                    connection.disconnect();

                } catch (Exception e) {
                    output = "CHECK RESULT\n\n"
                        + "Domain: " + domain + "\n"
                        + "Result: " + e.getMessage();
                }

                final String finalOutput = output;

                runOnUiThread(() -> {
                    results.setText(finalOutput);
                    scanButton.setEnabled(true);
                });

            }).start();
        });

        setContentView(layout);
    }
}
