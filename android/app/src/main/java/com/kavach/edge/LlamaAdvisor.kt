package com.kavach.edge

import android.util.Log
import org.json.JSONObject
import org.pytorch.executorch.extension.llm.LlmCallback
import org.pytorch.executorch.extension.llm.LlmGenerationConfig
import org.pytorch.executorch.extension.llm.LlmModule
import java.io.File

/**
 * Wraps ExecuTorch's LlmModule. It only turns a ready-made prompt into text: the prompt comes from
 * Python (kavach_bridge.prepare_*) and the text goes back to Python (kavach_bridge.finalize).
 * It has no say in the verdict.
 *
 * All methods block, so call them from a background thread.
 */
class LlamaAdvisor(private val modelDir: String = "/data/local/tmp/llama") {

    /** One generation's measurements, from ExecuTorch's own stats plus /proc/self/status. */
    data class Metrics(
        val promptTokens: Int, val generatedTokens: Int,
        val ttftMs: Long,            // inference start -> first generated token
        val prefillTokPerS: Double,  // prompt tokens / prefill time
        val decodeTokPerS: Double,   // generated tokens / decode time (same formula ExecuTorch logs)
        val peakRssMb: Double,       // VmHWM: the process's peak resident memory so far
        val raw: String,
    )

    private var module: LlmModule? = null
    var loadMs: Long = -1; private set
    var modelFile: String? = null; private set

    /** Find the .pte and tokenizer pushed with adb, then load the model (about 6 s on the V40e). */
    fun load() {
        val dir = File(modelDir)
        val pte = File(dir, "Llama-3.2-1B-Instruct-SpinQuant_INT4_EO8.pte").takeIf { it.canRead() }
            ?: dir.listFiles { f -> f.name.endsWith(".pte") }?.firstOrNull()
            ?: error("no .pte model in $modelDir (push it with adb, see README)")
        val tok = File(dir, "tokenizer.model").takeIf { it.canRead() }
            ?: error("no tokenizer.model in $modelDir")
        val t0 = System.nanoTime()
        // temperature 0 = always pick the most likely token, so the same evidence gives the same text
        val m = LlmModule(pte.path, tok.path, 0.0f)
        val rc = m.load()
        check(rc == 0) { "LlmModule.load() returned error code $rc" }
        loadMs = (System.nanoTime() - t0) / 1_000_000
        module = m
        modelFile = pte.name
        Log.i(TAG, "loaded ${pte.name} in $loadMs ms, rss=${rssMb("VmRSS")} MB")
    }

    val isLoaded get() = module != null

    /**
     * Run Llama on [prompt]. Each piece of text is passed to [onToken] as it is produced.
     * Returns the full text and the measurements.
     */
    fun generate(prompt: String, maxNewTokens: Int, onToken: (String) -> Unit): Pair<String, Metrics?> {
        val m = module ?: error("model not loaded")
        val sb = StringBuilder()
        var stats: String? = null
        val cfg = LlmGenerationConfig.create()
            .maxNewTokens(maxNewTokens)   // hard cap on output length
            .temperature(0.0f)
            .echo(false)                  // do not send the prompt back as output
            .build()
        m.resetContext()                  // each message is independent: no chat history in the KV cache
        val rc = m.generate(prompt, cfg, object : LlmCallback {
            override fun onResult(result: String) { sb.append(result); onToken(result) }
            override fun onStats(s: String) { stats = s }
        })
        if (rc != 0) Log.w(TAG, "generate() returned $rc")
        return sb.toString() to stats?.let { parseStats(it) }
    }

    fun stop() { module?.stop() }

    private fun parseStats(s: String): Metrics? = try {
        // field names from executorch/extension/llm/runner/stats.h
        val j = JSONObject(s)
        val start = j.getLong("inference_start_ms")
        val prefillEnd = j.getLong("prompt_eval_end_ms")
        val first = j.getLong("first_token_ms")
        val end = j.getLong("inference_end_ms")
        val pt = j.getInt("prompt_tokens"); val gt = j.getInt("generated_tokens")
        Metrics(pt, gt, first - start,
            pt * 1000.0 / maxOf(1, prefillEnd - start),
            gt * 1000.0 / maxOf(1, end - prefillEnd),
            rssMb("VmHWM"), s)
    } catch (e: Exception) { Log.w(TAG, "could not parse stats: $s", e); null }

    companion object {
        const val TAG = "KavachLLM"

        /** Read a memory line (VmRSS = now, VmHWM = peak) from /proc/self/status, in MB. */
        fun rssMb(key: String): Double = try {
            File("/proc/self/status").readLines().first { it.startsWith("$key:") }
                .split(Regex("\\s+"))[1].toDouble() / 1024.0
        } catch (e: Exception) { -1.0 }
    }
}
