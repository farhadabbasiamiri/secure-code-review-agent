# Running and deploying

Three ways to run the app, from simplest to most shareable. All of them serve the same Gradio app
on port 7860.

## 1. Locally with Python (what you'll use day to day)

Windows (PowerShell):

```powershell
python -m venv .venv
.venv\Scripts\python -m pip install -r requirements.txt
.venv\Scripts\python -m scra.app            # or: .venv\Scripts\python app.py
```

macOS / Linux:

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/python app.py
```

Open <http://127.0.0.1:7860>. The app listens only on your own machine. To let another computer on
your network open it, set `SCRA_HOST=0.0.0.0`.

Semgrep is installed by `pip` and runs natively on Windows, macOS and Linux. The app finds it
inside the virtualenv even when the virtualenv isn't activated.

## 2. Docker

Needs Docker Desktop (Windows/macOS) or Docker Engine (Linux), running.

```bash
docker build -t scra .
docker run --rm -p 7860:7860 scra                    # mock provider
docker run --rm -p 7860:7860 --env-file .env scra    # with your .env settings and keys
```

With Compose, which also persists the logs between runs:

```bash
docker compose up --build
```

**Ollama and Docker.** Inside a container, `localhost` means the container itself. Compose
points the app at `http://host.docker.internal:11434`, which is the Ollama running on your computer.
To run Ollama in a container instead:

```bash
docker compose --profile ollama up --build
docker compose exec ollama ollama pull qwen2.5-coder:7b
```

then set **Server URL** to `http://ollama:11434` on the LLM settings tab (or put
`SCRA_OLLAMA_URL=http://ollama:11434` in `.env`).

## 3. Hugging Face Spaces (public link)

A free CPU Space runs this Dockerfile as is.

1. Create a Space at <https://huggingface.co/new-space>: SDK **Docker**, template **Blank**,
   hardware **CPU basic**.
2. The Space's `README.md` must start with this header (Spaces read it to know how to run the app).
   Keep the project README as it is, and add the header only in the copy you push to the Space:

   ```yaml
   ---
   title: Secure Code Review Agent
   colorFrom: blue
   colorTo: gray
   sdk: docker
   app_port: 7860
   pinned: false
   ---
   ```
3. In the Space's **Settings → Variables and secrets**, add the variable `SCRA_HOSTED=1`.
4. Push the repository to the Space (`git remote add space https://huggingface.co/spaces/<you>/<name>`
   then `git push space main`). The build takes a few minutes.

**What `SCRA_HOSTED=1` changes.** On a public app, visitors must not be able to make the server
connect to addresses of their choosing (that would let them probe the host's network). In hosted
mode the local presets (Ollama, LM Studio, custom URL) are hidden, the Server URL field is locked,
and the backend ignores any URL a visitor sends. Visitors can still pick Groq, Gemini, OpenRouter or
OpenAI and paste their *own* key for their session.

**Using your key for visitors (optional).** Add a *secret* such as `GROQ_API_KEY` and a variable
`SCRA_PRESET=groq`. The app then starts on Groq with your key. Every visitor's review spends your
quota, so only do this for a demo you are watching.

Ollama can't run on a free Space (no GPU and too little memory), which is why the mock provider
and the hosted presets exist.

## Logs and monitoring

Every review appends one line to `logs/runs.jsonl`; approvals, drafted comments/patches, and
connection tests go to `logs/events.jsonl`. Both hold metadata only. View them in the **Monitoring**
tab or with `python -m scra.cli stats`. Set `SCRA_DISABLE_LOGS=1` to turn logging off, or
`SCRA_LOG_DIR` to move it. On Spaces the container's disk is not persistent, so logs reset on restart.

## All settings

See [`.env.example`](../.env.example). Settings come from the environment or a `.env` file in the
project folder; real environment variables take precedence over `.env`.
