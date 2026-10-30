# Secure Code Review Agent: Gradio app with Semgrep, ready for Docker or a Hugging Face Docker Space.
#   docker build -t scra .
#   docker run --rm -p 7860:7860 scra                       # mock LLM, offline-capable
#   docker run --rm -p 7860:7860 --env-file .env scra       # your settings and keys
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    GRADIO_ANALYTICS_ENABLED=False \
    SCRA_HOST=0.0.0.0 \
    SCRA_PORT=7860 \
    SCRA_LOG_DIR=/app/logs

WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .
# Hugging Face Spaces run containers as uid 1000; doing the same everywhere keeps behaviour identical.
RUN useradd --create-home --uid 1000 app && mkdir -p /app/logs && chown -R app:app /app
USER app

EXPOSE 7860
HEALTHCHECK --interval=30s --timeout=5s --start-period=60s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:7860/', timeout=4)"
CMD ["python", "app.py"]
