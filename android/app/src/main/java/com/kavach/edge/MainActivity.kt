package com.kavach.edge

import android.app.Activity
import android.graphics.Color
import android.graphics.Typeface
import android.os.Bundle
import android.text.InputType
import android.util.Log
import android.view.ViewGroup.LayoutParams.MATCH_PARENT
import android.view.ViewGroup.LayoutParams.WRAP_CONTENT
import android.view.WindowManager
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import com.chaquo.python.PyObject
import com.chaquo.python.Python
import com.chaquo.python.android.AndroidPlatform
import org.json.JSONObject
import java.io.File
import java.util.concurrent.Executors

/**
 * Kavach Edge main screen.
 *   1. Python (detector + risk fusion) gives the verdict, which is shown at once.
 *   2. Llama 3.2 1B (ExecuTorch, CPU) writes the explanation, streamed as a draft.
 *   3. Python checks Llama's text; the screen shows it, or the playbook template if a check fails.
 */
class MainActivity : Activity() {
    // Two worker threads: the 6 s model load must not delay the detector's verdict.
    private val pyExec = Executors.newSingleThreadExecutor()
    private val llmExec = Executors.newSingleThreadExecutor()
    private val llama = LlamaAdvisor()
    @Volatile private var llamaError: String? = null

    private lateinit var input: EditText
    private lateinit var sender: EditText
    private lateinit var verdictView: TextView
    private lateinit var adviceView: TextView
    private lateinit var statusView: TextView
    private lateinit var buttons: List<Button>

    private val bridge: PyObject by lazy { Python.getInstance().getModule("kavach_bridge") }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // Funtouch OS freezes apps it thinks are idle; keep the screen on while the app is open.
        window.addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON)
        buildUi()
        val tPy = System.nanoTime()
        if (!Python.isStarted()) Python.start(AndroidPlatform(this))
        val pythonStartMs = (System.nanoTime() - tPy) / 1e6

        // Benchmark hooks (bench/BENCHMARK_PROTOCOL.md). Llama is NOT loaded in these modes, so the
        // detector's memory numbers are the detector's alone.
        //   --ez coldstart true                       one cold-start sample (run after am force-stop)
        //   --es bench_args '["--label","phone_arm64",...]'   run_bench.py, copy pushed to files/kbench
        if (intent.getBooleanExtra("coldstart", false)) {
            pyExec.execute {
                val r = bridge.callAttr("cold_start", File(getExternalFilesDir(null), "coldstart.jsonl").path, pythonStartMs).toString()
                runOnUiThread { statusView.text = "Cold start: $r" }
            }
            return
        }
        // bench_args_file: path of a JSON list of run_bench.py arguments (avoids shell quoting of the device note)
        (intent.getStringExtra("bench_args") ?: intent.getStringExtra("bench_args_file")?.let { File(it).readText() })?.let { args ->
            status("Running run_bench.py ... (Llama not loaded)")
            pyExec.execute {
                val r = bridge.callAttr("run_bench", File(getExternalFilesDir(null), "kbench").path, args).toString()
                runOnUiThread { statusView.text = "Bench finished: $r" }
            }
            return
        }

        // Dev hook for the phone-vs-laptop parity check (see Step 2):
        //   adb shell am start -n com.kavach.edge/.MainActivity --es score_in /data/local/tmp/kavach/parity_in.jsonl
        intent.getStringExtra("score_in")?.let { inPath ->
            pyExec.execute {
                val outPath = File(getExternalFilesDir(null), "parity_out.jsonl").path
                val r = bridge.callAttr("score_file", inPath, outPath).toString()
                Log.i(TAG, "score_file: $r")
                runOnUiThread { statusView.text = "Scored: $r" }
            }
            return
        }

        pyExec.execute { bridge.callAttr("selftest") }   // warm up Python + detector
        status("Loading Llama 3.2 1B ...")
        llmExec.execute {
            try {
                llama.load()
                status("Llama ready: ${llama.modelFile} (loaded in ${llama.loadMs} ms). Offline, on-device.")
            } catch (e: Throwable) {
                Log.e(TAG, "Llama load failed", e)
                llamaError = e.message
                status("Llama not available (${e.message}). Using template explanations.")
            }
        }

        // Dev hook for scripted runs and benchmarks: fill in a message and check it at once.
        //   adb shell am start -n com.kavach.edge/.MainActivity --es text "..." [--es sender VM-SBIBNK] [--ez url true]
        intent.getStringExtra("text")?.let { t ->
            input.setText(t)
            sender.setText(intent.getStringExtra("sender") ?: "")
            analyze(intent.getBooleanExtra("url", false))
        }

        // Dev hook for test sets and benchmarks: load Llama once, then run every line of a JSONL file
        // ({"id","text","sender"}) through the full pipeline. Results go to llm_runs.jsonl with the id.
        //   adb shell am start -n com.kavach.edge/.MainActivity --es batch /data/local/tmp/kavach/injection_set.jsonl
        intent.getStringExtra("batch")?.let { path -> runBatch(path) }
    }

    private fun runBatch(path: String) = llmExec.execute {   // queued after the model load
        val lines = File(path).readLines().filter { it.isNotBlank() }
        lines.forEachIndexed { i, line ->
            val j = JSONObject(line)
            val pkg = JSONObject(bridge.callAttr("prepare_message", j.getString("text"),
                j.optString("sender").ifEmpty { null }).toString())
            runOnUiThread { showVerdict(pkg, 0.0) }
            explain(pkg, j.optString("id"))
            status("Batch ${i + 1}/${lines.size}")
        }
        status("Batch done: ${lines.size} items")
    }

    // ------------------------------------------------------------------------------- analysis
    private fun analyze(isUrl: Boolean) {
        val text = input.text.toString().trim()
        if (text.isEmpty()) return
        val snd = sender.text.toString().trim()
        setBusy(true)
        verdictView.text = "Checking ..."; verdictView.setBackgroundColor(Color.LTGRAY)
        adviceView.text = ""

        pyExec.execute {
            try {
                val t0 = System.nanoTime()
                val pkgJson = if (isUrl) bridge.callAttr("prepare_url", text).toString()
                              else bridge.callAttr("prepare_message", text, snd.ifEmpty { null }).toString()
                val detMs = (System.nanoTime() - t0) / 1e6
                val pkg = JSONObject(pkgJson)
                runOnUiThread { showVerdict(pkg, detMs) }
                // Llama runs on its own thread (it waits there if the model is still loading).
                llmExec.execute { explain(pkg) }
            } catch (e: Throwable) {
                Log.e(TAG, "analysis failed", e)
                runOnUiThread { verdictView.text = "Error: ${e.message}"; setBusy(false) }
            }
        }
    }

    private fun explain(pkg: JSONObject, runId: String = "") {
        val evidence = pkg.getJSONObject("evidence").toString()
        if (!llama.isLoaded) {   // no model: show the template, and say so
            runOnUiThread {
                showFinal(pkg.getJSONObject("fallback"), "Template explanation (Llama not loaded: $llamaError)")
                setBusy(false)
            }
            return
        }
        runOnUiThread { adviceView.setTextColor(Color.GRAY); adviceView.text = "" }
        val (raw, m) = llama.generate(pkg.getString("prompt"), pkg.getInt("max_new_tokens")) { piece ->
            runOnUiThread { adviceView.append(piece) }   // draft, shown grey until checked
        }
        val fin = JSONObject(bridge.callAttr("finalize", raw, evidence).toString())
        val check = fin.getJSONObject("check")
        val label = if (fin.getString("source") == "llama") "Explained by Llama 3.2 1B on this phone (checked against the evidence)"
                    else "Template explanation (Llama's text failed a check: ${check.getJSONArray("reasons").join(", ")})"
        m?.let { logMetrics(it, pkg, fin, raw, runId) }
        runOnUiThread {
            showFinal(fin, label)
            m?.let { statusView.text = "TTFT ${it.ttftMs} ms | decode %.1f tok/s | %d tokens | peak RSS %.0f MB"
                .format(it.decodeTokPerS, it.generatedTokens, it.peakRssMb) }
            setBusy(false)
        }
    }

    // ------------------------------------------------------------------------------- display
    private fun showVerdict(pkg: JSONObject, detMs: Double) {
        val v = pkg.getJSONObject("verdict")
        val color = when (v.getString("label")) {
            "dangerous" -> Color.rgb(198, 40, 40); "suspicious" -> Color.rgb(239, 108, 0); else -> Color.rgb(46, 125, 50)
        }
        verdictView.setBackgroundColor(color)
        verdictView.text = "${pkg.getString("headline")}\nRisk ${(v.getDouble("risk_score") * 100).toInt()}% " +
            "(${v.getString("confidence")} confidence)" +
            (pkg.optString("category_text").takeIf { it.isNotEmpty() && v.getString("label") != "safe" }?.let { "\nLooks like: $it" } ?: "")
        statusView.text = "Detector: %.0f ms".format(detMs) + if (llama.isLoaded) " | Llama explaining ..." else ""
    }

    private fun showFinal(out: JSONObject, sourceLabel: String) {
        val actions = out.getJSONArray("actions")
        val steps = (0 until actions.length()).joinToString("\n") { "${it + 1}. ${actions.getString(it)}" }
        adviceView.setTextColor(Color.BLACK)
        // Steps always come word for word from the playbook (Python), never from Llama.
        adviceView.text = out.getString("explanation") + "\n\nWhat to do:\n$steps" +
            "\n\n- $sourceLabel\n- Automatic check: it can be wrong. Never tap links in suspicious messages."
    }

    private fun logMetrics(m: LlamaAdvisor.Metrics, pkg: JSONObject, fin: JSONObject, raw: String, runId: String) {
        val row = JSONObject().apply {
            put("ts", System.currentTimeMillis()); put("id", runId); put("model", llama.modelFile); put("load_ms", llama.loadMs)
            put("verdict", pkg.getJSONObject("verdict").getString("label")); put("source", fin.getString("source"))
            put("prompt_tokens", m.promptTokens); put("generated_tokens", m.generatedTokens)
            put("ttft_ms", m.ttftMs); put("prefill_tok_s", m.prefillTokPerS); put("decode_tok_s", m.decodeTokPerS)
            put("peak_rss_mb", m.peakRssMb); put("et_stats", JSONObject(m.raw))
            // Audit trail: what Llama wrote and what the checks decided (no SMS text is stored).
            put("llm_raw", raw); put("check", fin.getJSONObject("check")); put("shown", fin.getString("explanation"))
        }
        Log.i(LlamaAdvisor.TAG, "metrics: $row")
        // One line per run, pulled later with adb for the benchmark report.
        File(getExternalFilesDir(null), "llm_runs.jsonl").appendText(row.toString() + "\n")
    }

    private fun status(s: String) = runOnUiThread { statusView.text = s }
    private fun setBusy(b: Boolean) = buttons.forEach { it.isEnabled = !b }

    // ------------------------------------------------------------------------------- layout
    private fun buildUi() {
        val pad = 32
        val col = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; setPadding(pad, pad, pad, pad) }
        col.addView(TextView(this).apply { text = "Kavach Edge"; textSize = 22f; setTypeface(null, Typeface.BOLD) })
        col.addView(TextView(this).apply { text = "Scam check that runs fully on this phone. Paste an SMS or a link."; textSize = 13f })
        input = EditText(this).apply {
            hint = "Paste the SMS text or a link"; minLines = 4; gravity = android.view.Gravity.TOP
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_MULTI_LINE
        }
        sender = EditText(this).apply { hint = "Sender (optional), e.g. VM-SBIBNK or +9198..."; isSingleLine = true }
        col.addView(input, LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT))
        col.addView(sender, LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT))
        val row = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL }
        val bSms = Button(this).apply { text = "Check SMS"; setOnClickListener { analyze(false) } }
        val bUrl = Button(this).apply { text = "Check link"; setOnClickListener { analyze(true) } }
        row.addView(bSms); row.addView(bUrl); col.addView(row)
        buttons = listOf(bSms, bUrl)
        verdictView = TextView(this).apply { textSize = 18f; setTextColor(Color.WHITE); setPadding(24, 24, 24, 24); setTypeface(null, Typeface.BOLD) }
        adviceView = TextView(this).apply { textSize = 15f; setPadding(0, 24, 0, 24); setTextIsSelectable(true) }
        statusView = TextView(this).apply { textSize = 11f; setTextColor(Color.DKGRAY) }
        col.addView(verdictView, LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT))
        col.addView(adviceView); col.addView(statusView)
        setContentView(ScrollView(this).apply { setBackgroundColor(Color.WHITE); addView(col) })
    }

    override fun onDestroy() { llama.stop(); super.onDestroy() }

    companion object { const val TAG = "Kavach" }
}
