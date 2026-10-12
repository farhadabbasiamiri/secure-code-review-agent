# Choosing and connecting a model

The agent needs a language model that supports **tool calling**: the model is handed three tools
(Semgrep scan, dependency check, guidance lookup), decides which to call, reads the results, and
writes the findings. Everything else (the scanners, the knowledge base, the grounding guard) runs
locally whatever model you pick.

You can switch models at any time in the app's **LLM settings** tab. Nothing is saved there:
the settings last for your browser session. To make a choice stick, put it in a `.env` file
(copy `.env.example`).

## Which one should I use?

| Option | Cost | Setup | Speed on a laptop without a GPU | Code leaves your machine? |
|--------|------|-------|----------------------------------|---------------------------|
| **Mock** | Free | None | Instant (only Semgrep's ~5 s) | No |
| **Ollama** | Free | Install app, download a 2–5 GB model | Slow: roughly 1–5 min per review | No |
| **LM Studio** | Free | Install app, download a model, start server | Same as Ollama | No |
| **Groq** | Free tier | Sign up, copy a key | Fast: a few seconds | Yes, masked |
| **Google Gemini** | Free tier | Sign in, copy a key | Fast | Yes, masked |
| **OpenRouter** | Free models + paid | Sign up, copy a key | Depends on the model | Yes, masked |
| **OpenAI** | Paid | Billing + key | Fast | Yes, masked |

Suggested path:

1. **Learn the app with Mock.** It exercises every feature: real tools, the approval step,
   patch drafts, monitoring. Only the explanation text is templated.
2. **For the demo and the report, use a real model.** Groq's free tier is the quickest way to see
   real LLM explanations. Ollama is the answer to "does any code leave the machine?" and is what
   the brief suggests (Ollama or LM Studio with Qwen, Llama, Gemma, Mistral, or Phi).

"Masked" means hardcoded secrets are replaced before anything is sent (`ghp_1234...` becomes
`ghp_************`), so a key someone pasted into their code does not leak to the provider. The
code itself is still sent. Free tiers of hosted APIs may use inputs to improve their models; check
the provider's terms before reviewing anything that isn't toy code.

---

## Mock (no setup)

Selected by default. The mock provider follows the same protocol as a real model: it calls the
scanner, then one guidance lookup per issue type, then writes structured findings from templates
plus the retrieved guidance. Every finding says "Explanation and fix written by the offline mock
provider", so nobody mistakes it for model output.

## Ollama (local, free)

1. **Install.** Download the Windows installer from <https://ollama.com/download> and run it.
   Ollama then runs in the background (system tray) and listens on `http://localhost:11434`.
2. **Download a model** in PowerShell. Pick one:

   | Model | Download | Notes |
   |-------|----------|-------|
   | `qwen2.5-coder:7b` | ~4.7 GB | Best explanations of the small models; slow without a GPU |
   | `llama3.2:3b` | ~2.0 GB | Roughly twice as fast; explanations are plainer |
   | `qwen2.5:3b` | ~1.9 GB | Similar to llama3.2:3b |

   ```powershell
   ollama pull qwen2.5-coder:7b
   ollama list                      # shows what is installed
   ```
   With 16 GB of RAM any of these fits. Ollama runs them on the CPU when there is no supported
   GPU (integrated Intel graphics is not used), so a 7B model takes a while per answer.
3. **Connect.** In the app, open **LLM settings**, choose *Ollama (local, free)*, select
   **Fetch models**, pick the model, then **Test connection**. You should see three ticks:
   server reachable, model present, tool calling works.
4. **Allow enough time.** A review makes 3 to 6 model calls. On a CPU, raise
   *Per-call timeout* to 300 s and *Whole-review time limit* to 600 s. If the limit is hit, the
   review still shows every tool finding with template text and a note saying so.

The first call after starting is slow because the model loads into memory. The Monitoring tab
shows how long reviews actually take on your machine.

To make Ollama the default (CLI too), put this in `.env`:

```
SCRA_LLM=ollama
SCRA_OLLAMA_MODEL=qwen2.5-coder:7b
SCRA_LLM_TIMEOUT=300
SCRA_AGENT_DEADLINE=600
```

## LM Studio (local, free)

1. Install from <https://lmstudio.ai>.
2. Search for and download a model with tool-use support, for example *Qwen2.5 Coder 7B Instruct*.
3. Open the **Developer** tab, load the model, and start the server (`http://localhost:1234/v1`).
4. In the app choose *LM Studio*, **Fetch models**, pick the loaded model, **Test connection**.

## Groq (free tier, API key)

1. Sign in at <https://console.groq.com>, open **API Keys**, create a key, and copy it.
2. In the app choose *Groq*, paste the key into **API key**, then **Fetch models** and
   **Test connection**. The default model is `llama-3.3-70b-versatile`; if Groq has retired it,
   pick another tool-capable model from the fetched list.
3. To avoid pasting each time, add `GROQ_API_KEY=...` to `.env`. The key field then says it is
   using the environment value.

Free-tier rate limits apply. If a review fails with HTTP 429, wait a minute.

## Google Gemini (free tier, API key)

1. Create a key at <https://aistudio.google.com/apikey>.
2. Choose *Google Gemini*, paste the key, **Fetch models**, **Test connection**. The app uses
   Google's OpenAI-compatible endpoint. Fetched ids may look like `models/gemini-...`; if a full id
   fails, use the part after `models/`.
3. Or set `GEMINI_API_KEY=...` in `.env`.

## OpenRouter (API key)

1. Create a key at <https://openrouter.ai/keys>.
2. Choose *OpenRouter*, paste the key, **Fetch models**. Free models end in `:free`; choose one
   that lists tool support on its OpenRouter page.
3. Or set `OPENROUTER_API_KEY=...` in `.env`.

## OpenAI (paid)

Create a key at <https://platform.openai.com/api-keys> (billing required), choose *OpenAI*, paste it
or set `OPENAI_API_KEY`.

## Any other OpenAI-compatible server

vLLM, the llama.cpp server, and many others speak the same `/v1/chat/completions` API. Choose
*Custom OpenAI-compatible server*, enter the base URL (ending in `/v1`) and model id. For the CLI:

```
SCRA_LLM=openai
SCRA_OPENAI_BASE_URL=http://localhost:8000/v1
SCRA_OPENAI_MODEL=your-model-id
SCRA_OPENAI_API_KEY=only-if-needed
```

---

## What happens to your key

- A key pasted in the app is held in server memory for your browser session and sent only to the
  provider you chose. It is never written to disk or to the logs, and if a provider's error message
  echoes it back, the app masks it before showing the error.
- A key in `.env` stays on your machine. `.env` is gitignored. Never commit it, and never set a
  key as a variable on a *public* deployment unless you are happy for visitors to spend it.

## Troubleshooting

| What you see | What it means | Fix |
|--------------|---------------|-----|
| "nothing is answering at that address" | No server at that URL | Start Ollama / LM Studio's server; check the port |
| "Model 'x' is not on this server" | Model not downloaded | `ollama pull x`, or pick one from **Fetch models** |
| "Model replied but did not call the tool" | The model can't do tool calling | Choose a tool-capable model (the ones listed above work) |
| HTTP 401 | Wrong or expired key | Create a new key |
| HTTP 404 on chat | Wrong model id or URL | **Fetch models** and pick from the list |
| HTTP 429 | Rate limit | Wait, or switch provider |
| "Agent hit the time limit" | Slow local model | Raise both time limits on the settings tab |
| Findings say "written by a fixed template" | The model skipped that issue or failed | Normal fallback; nothing found by a tool is ever hidden |

A weaker model never makes the review *less complete*: detection comes from the tools, and any tool
hit the model leaves out is added back. A weaker model only makes the explanations less helpful.
