package io.github.beakthoven.tsoss.verification;

import android.app.Activity;
import android.os.Bundle;
import android.util.Log;
import io.github.beakthoven.trickystoreoss.harness.Harness;

public final class ValidationActivity extends Activity {
    @Override public void onCreate(Bundle state) {
        super.onCreate(state);
        new Thread(new Runnable() {
            @Override public void run() {
                String mode = getIntent().getStringExtra("mode");
                if (mode == null) mode = "full";
                String runId = getIntent().getStringExtra("run-id");
                int iterations = getIntent().getIntExtra("iterations", 500);
                int result = Harness.runInApp(mode, runId, iterations);
                Log.i("TSOSS-VALIDATION", "EXIT " + result);
                runOnUiThread(new Runnable() {
                    @Override public void run() { finish(); }
                });
            }
        }, "tsoss-validation").start();
    }
}
