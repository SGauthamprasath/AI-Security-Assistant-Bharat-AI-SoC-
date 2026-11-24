package com.kavach.edge

import android.app.Activity
import android.os.Bundle
import android.widget.ScrollView
import android.widget.TextView
import com.chaquo.python.Python
import com.chaquo.python.android.AndroidPlatform
import org.json.JSONObject
import kotlin.concurrent.thread

/** Step 1 smoke test: start Python, load the detector, analyse one SMS, show the result. */
class MainActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val out = TextView(this).apply { setPadding(32, 32, 32, 32); textSize = 13f; setTextIsSelectable(true) }
        setContentView(ScrollView(this).apply { addView(out) })
        out.text = "Starting Python..."

        // Python work runs off the UI thread so the screen never freezes.
        thread {
            val text = try {
                val t0 = System.nanoTime()
                if (!Python.isStarted()) Python.start(AndroidPlatform(this))
                val startMs = (System.nanoTime() - t0) / 1e6
                val bridge = Python.getInstance().getModule("kavach_bridge")
                // Dev hook for the phone-vs-laptop parity check:
                //   adb shell am start -n com.kavach.edge/.MainActivity --es score_in /data/local/tmp/kavach/parity_in.jsonl
                // Results go to the app's external files dir, which adb can pull.
                intent.getStringExtra("score_in")?.let { inPath ->
                    val outPath = java.io.File(getExternalFilesDir(null), "parity_out.jsonl").path
                    val r = bridge.callAttr("score_file", inPath, outPath).toString()
                    android.util.Log.i("Kavach", "score_file: $r")
                    runOnUiThread { out.text = "Scored:\n$r" }
                    return@thread
                }
                val report = JSONObject(bridge.callAttr("selftest").toString())
                report.put("python_start_ms", startMs)
                android.util.Log.i("Kavach", "selftest: $report")
                report.toString(2)
            } catch (e: Throwable) {
                android.util.Log.e("Kavach", "selftest failed", e)
                "FAILED:\n$e"
            }
            runOnUiThread { out.text = text }
        }
    }
}
