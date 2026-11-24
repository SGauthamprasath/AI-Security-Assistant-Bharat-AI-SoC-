package com.kavach.edge

import android.app.Activity
import android.content.ClipboardManager
import android.graphics.Typeface
import android.graphics.drawable.GradientDrawable
import android.os.Bundle
import android.text.Editable
import android.text.TextWatcher
import android.util.Log
import android.view.Gravity
import android.view.View
import android.view.WindowManager
import android.view.inputmethod.InputMethodManager
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ProgressBar
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
 *   2. Llama 3.2 1B (ExecuTorch, CPU) writes the explanation, streamed as a grey draft.
 *   3. Python checks Llama's text; the screen shows it, or the playbook template if a check fails.
 * The layout is res/layout/activity_main.xml; this class only fills it in.
 */
class MainActivity : Activity() {
    // Two worker threads: the model load (4-7 s) must not delay the detector's verdict.
    private val pyExec = Executors.newSingleThreadExecutor()
    private val llmExec = Executors.newSingleThreadExecutor()
    private val llama = LlamaAdvisor()
    @Volatile private var llamaError: String? = null

    // Views from res/layout/activity_main.xml
    private lateinit var input: EditText
    private lateinit var sender: EditText
    private lateinit var checkButton: Button
    private lateinit var modeHint: TextView
    private lateinit var modelDot: View
    private lateinit var modelText: TextView
    private lateinit var results: LinearLayout
    private lateinit var verdictCard: LinearLayout
    private lateinit var verdictIcon: TextView
    private lateinit var verdictTitle: TextView
    private lateinit var riskBar: ProgressBar
    private lateinit var verdictRisk: TextView
    private lateinit var verdictCategory: TextView
    private lateinit var sourceChip: TextView
    private lateinit var explanation: TextView
    private lateinit var sourceNote: TextView
    private lateinit var stepsCard: LinearLayout
    private lateinit var stepsList: LinearLayout
    private lateinit var statusView: TextView      // footer line: timings, and dev-hook messages
    private lateinit var scroll: ScrollView

    private val bridge: PyObject by lazy { Python.getInstance().getModule("kavach_bridge") }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // The phone's OS freezes apps it thinks are idle; keep the screen on while the app is open.
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
            modelState(ModelState.LOADING, "Benchmark mode: cold start")
            pyExec.execute {
                val r = bridge.callAttr("cold_start", File(getExternalFilesDir(null), "coldstart.jsonl").path, pythonStartMs).toString()
                runOnUiThread { statusView.text = "Cold start: $r" }
            }
            return
        }
        // bench_args_file: path of a JSON list of run_bench.py arguments (avoids shell quoting of the device note)
        (intent.getStringExtra("bench_args") ?: intent.getStringExtra("bench_args_file")?.let { File(it).readText() })?.let { args ->
            modelState(ModelState.LOADING, "Benchmark mode: run_bench.py (Llama not loaded)")
            status("Running run_bench.py ...")
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
        modelState(ModelState.LOADING, "Loading Llama 3.2 1B on this phone ...")
        llmExec.execute {
            try {
                llama.load()
                modelState(ModelState.READY, "Llama 3.2 1B ready · offline · loaded in %.1f s".format(llama.loadMs / 1000.0))
            } catch (e: Throwable) {
                Log.e(TAG, "Llama load failed", e)
                llamaError = e.message
                modelState(ModelState.ERROR, "Llama not available · fixed explanations only")
            }
        }

        // Dev hook for scripted runs and benchmarks: fill in a message and check it at once.
        //   adb shell am start -n com.kavach.edge/.MainActivity --es text "..." [--es sender VM-SBIBNK] [--ez url true]
        intent.getStringExtra("text")?.let { t ->
            input.setText(t)
            sender.setText(intent.getStringExtra("sender") ?: "")
            // --ez url true/false forces the mode; without it, the same rule as the Check button decides
            analyze(if (intent.hasExtra("url")) intent.getBooleanExtra("url", false) else looksLikeLink(t.trim()))
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
    /** A single token that looks like a web address is checked as a link; anything else as an SMS. */
    private fun looksLikeLink(t: String): Boolean =
        !t.contains(Regex("\\s")) && t.contains('.') &&
            (t.startsWith("http://", true) || t.startsWith("https://", true) || t.startsWith("www.", true) ||
             Regex("^[a-z0-9-]+(\\.[a-z0-9-]+)+(/.*)?$", RegexOption.IGNORE_CASE).matches(t))

    private fun analyze(isUrl: Boolean) {
        val text = input.text.toString().trim()
        if (text.isEmpty()) return
        val snd = sender.text.toString().trim()
        setBusy(true)
        showChecking()

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
                runOnUiThread { verdictTitle.text = "Error: ${e.message}"; setBusy(false) }
            }
        }
    }

    private fun explain(pkg: JSONObject, runId: String = "") {
        val evidence = pkg.getJSONObject("evidence").toString()
        if (!llama.isLoaded) {   // no model: show the template, and say so
            runOnUiThread {
                showFinal(pkg.getJSONObject("fallback"), "Llama is not loaded on this phone ($llamaError), so a fixed explanation is shown.")
                setBusy(false)
            }
            return
        }
        runOnUiThread { showDraftStart() }
        val (raw, m) = llama.generate(pkg.getString("prompt"), pkg.getInt("max_new_tokens")) { piece ->
            runOnUiThread { if (!piece.startsWith("<|")) explanation.append(piece) }   // draft, grey until checked
        }
        val fin = JSONObject(bridge.callAttr("finalize", raw, evidence).toString())
        val check = fin.getJSONObject("check")
        val label = if (fin.getString("source") == "llama") "Written by Llama 3.2 1B on this phone and checked against the detector's evidence."
                    else "Llama's text did not pass a safety check (${check.getJSONArray("reasons").join(", ").replace("\"", "")}), so a fixed explanation is shown."
        m?.let { logMetrics(it, pkg, fin, raw, runId) }
        runOnUiThread {
            showFinal(fin, label)
            m?.let { statusView.text = statusView.text.toString() + "  ·  Llama: first word %.1f s, %.1f tokens/s, %d tokens, peak RAM %.0f MB"
                .format(it.ttftMs / 1000.0, it.decodeTokPerS, it.generatedTokens, it.peakRssMb) }
            setBusy(false)
        }
    }

    // ------------------------------------------------------------------------------- display
    private enum class ModelState { LOADING, READY, ERROR }

    /** Header chip: coloured dot + text for the Llama model state. */
    private fun modelState(st: ModelState, text: String) = runOnUiThread {
        val c = when (st) { ModelState.LOADING -> R.color.dot_loading; ModelState.READY -> R.color.dot_ready; ModelState.ERROR -> R.color.dot_error }
        (modelDot.background.mutate() as GradientDrawable).setColor(getColor(c))
        modelText.text = text
    }

    private fun dp(v: Int) = (v * resources.displayMetrics.density).toInt()

    private fun roundedColor(c: Int) = GradientDrawable().apply { cornerRadius = dp(16).toFloat(); setColor(c) }

    /** Grey "Checking" card while the detector runs (a few ms; mostly visible on the first check). */
    private fun showChecking() {
        results.visibility = View.VISIBLE
        verdictCard.background = roundedColor(getColor(R.color.pending))
        verdictIcon.text = "…"; verdictTitle.text = "Checking ..."
        riskBar.progress = 0; verdictRisk.text = ""; verdictCategory.visibility = View.GONE
        explanation.text = ""; sourceChip.text = ""; sourceNote.visibility = View.GONE
        stepsCard.visibility = View.GONE
    }

    /** Verdict from risk fusion: shown at once, before Llama starts. */
    private fun showVerdict(pkg: JSONObject, detMs: Double) {
        results.visibility = View.VISIBLE
        val v = pkg.getJSONObject("verdict")
        val label = v.getString("label")
        val (color, icon) = when (label) {
            "dangerous" -> R.color.danger to "⚠"      // warning sign
            "suspicious" -> R.color.warning to "!"
            else -> R.color.safe to "✓"               // check mark
        }
        verdictCard.background = roundedColor(getColor(color))
        verdictIcon.text = icon
        verdictTitle.text = pkg.getString("headline")
        val risk = (v.getDouble("risk_score") * 100).toInt()
        riskBar.progress = risk
        verdictRisk.text = "Risk $risk%  ·  ${v.getString("confidence")} confidence"
        val cat = pkg.optString("category_text")
        if (cat.isNotEmpty() && label != "safe") { verdictCategory.text = "Looks like: $cat"; verdictCategory.visibility = View.VISIBLE }
        else verdictCategory.visibility = View.GONE
        statusView.text = if (detMs > 0) "Detector: %.0f ms on this phone".format(detMs) else ""
        if (llama.isLoaded) showDraftStart()
    }

    private fun showDraftStart() {
        sourceChip.text = "LLAMA · WRITING ..."
        explanation.setTextColor(getColor(R.color.draft))
        explanation.text = ""
        sourceNote.visibility = View.GONE
    }

    /** Final, checked text plus the playbook steps. Steps never come from Llama. */
    private fun showFinal(out: JSONObject, sourceLabel: String) {
        val fromLlama = out.optString("source") == "llama"
        sourceChip.text = if (fromLlama) "ON-DEVICE AI · CHECKED" else "FIXED EXPLANATION"
        explanation.setTextColor(getColor(R.color.text))
        explanation.text = out.getString("explanation")
        sourceNote.text = sourceLabel; sourceNote.visibility = View.VISIBLE

        stepsList.removeAllViews()
        val actions = out.getJSONArray("actions")
        for (i in 0 until actions.length()) stepsList.addView(stepRow(i + 1, actions.getString(i)))
        stepsCard.visibility = if (actions.length() > 0) View.VISIBLE else View.GONE
    }

    /** One "What to do" row: a numbered circle and the playbook text. */
    private fun stepRow(n: Int, text: String) = LinearLayout(this).apply {
        orientation = LinearLayout.HORIZONTAL
        setPadding(0, dp(10), 0, 0)
        addView(TextView(this@MainActivity).apply {
            this.text = n.toString(); gravity = Gravity.CENTER; textSize = 13f
            setTextColor(getColor(R.color.primary)); setTypeface(typeface, Typeface.BOLD)
            setBackgroundResource(R.drawable.bg_step_num)
        }, LinearLayout.LayoutParams(dp(26), dp(26)))
        addView(TextView(this@MainActivity).apply {
            this.text = text; textSize = 15f; setTextColor(getColor(R.color.text)); setPadding(dp(12), dp(2), 0, 0)
        }, LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f))
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

    private fun setBusy(b: Boolean) = runOnUiThread {
        checkButton.isEnabled = !b
        checkButton.text = if (b) "Checking ..." else "Check"
    }

    // ------------------------------------------------------------------------------- layout
    private fun buildUi() {
        setContentView(R.layout.activity_main)
        input = findViewById(R.id.input); sender = findViewById(R.id.sender)
        checkButton = findViewById(R.id.btnCheck); modeHint = findViewById(R.id.modeHint)
        modelDot = findViewById(R.id.modelDot); modelText = findViewById(R.id.modelText)
        results = findViewById(R.id.results); verdictCard = findViewById(R.id.verdictCard)
        verdictIcon = findViewById(R.id.verdictIcon); verdictTitle = findViewById(R.id.verdictTitle)
        riskBar = findViewById(R.id.riskBar); verdictRisk = findViewById(R.id.verdictRisk)
        verdictCategory = findViewById(R.id.verdictCategory); sourceChip = findViewById(R.id.sourceChip)
        explanation = findViewById(R.id.explanation); sourceNote = findViewById(R.id.sourceNote)
        stepsCard = findViewById(R.id.stepsCard); stepsList = findViewById(R.id.stepsList)
        statusView = findViewById(R.id.statusView); scroll = findViewById(R.id.scroll)

        // Edge-to-edge (Android 15+): keep the header below the status bar and the last card above the
        // gesture bar by adding the system-bar sizes to the existing padding.
        val header = findViewById<View>(R.id.header); val content = findViewById<View>(R.id.content)
        val hTop = header.paddingTop; val cBottom = content.paddingBottom
        findViewById<View>(R.id.root).setOnApplyWindowInsetsListener { _, insets ->
            @Suppress("DEPRECATION") val top = insets.systemWindowInsetTop
            @Suppress("DEPRECATION") val bottom = insets.systemWindowInsetBottom
            header.setPadding(header.paddingLeft, hTop + top, header.paddingRight, header.paddingBottom)
            content.setPadding(content.paddingLeft, content.paddingTop, content.paddingRight, cBottom + bottom)
            insets
        }

        checkButton.setOnClickListener {
            hideKeyboard()
            analyze(looksLikeLink(input.text.toString().trim()))
            scroll.post { scroll.smoothScrollTo(0, results.top) }
        }
        findViewById<TextView>(R.id.btnPaste).setOnClickListener {
            val clip = (getSystemService(CLIPBOARD_SERVICE) as ClipboardManager).primaryClip
            val t = clip?.takeIf { it.itemCount > 0 }?.getItemAt(0)?.coerceToText(this)?.toString()
            if (!t.isNullOrBlank()) input.setText(t.trim())
        }
        findViewById<TextView>(R.id.btnClear).setOnClickListener {
            input.setText(""); sender.setText(""); results.visibility = View.GONE; statusView.text = ""
        }
        // Tell the user how the text will be checked, as they type.
        input.addTextChangedListener(object : TextWatcher {
            override fun afterTextChanged(e: Editable?) {
                val t = e?.toString()?.trim().orEmpty()
                modeHint.text = when {
                    t.isEmpty() -> "Checks an SMS, or a link on its own"
                    looksLikeLink(t) -> "Will be checked as a link"
                    else -> "Will be checked as an SMS"
                }
            }
            override fun beforeTextChanged(s: CharSequence?, a: Int, b: Int, c: Int) {}
            override fun onTextChanged(s: CharSequence?, a: Int, b: Int, c: Int) {}
        })
    }

    private fun hideKeyboard() {
        (getSystemService(INPUT_METHOD_SERVICE) as InputMethodManager).hideSoftInputFromWindow(input.windowToken, 0)
    }

    override fun onDestroy() { llama.stop(); super.onDestroy() }

    companion object { const val TAG = "Kavach" }
}
