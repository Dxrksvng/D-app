# RiskGuard backend + reference web app. Standard library only, no pip install needed.
FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PORT=8080 TRUST_PROXY=1 HOME_PAGE=wallet.html
WORKDIR /app
COPY backend ./backend
COPY web ./web
COPY data/seed ./data/seed
COPY openapi.yaml ./
RUN useradd -r -u 10001 app && mkdir -p /app/data && chown -R app /app/data
USER app
EXPOSE 8080
# Cloud hosts (Render, Cloud Run, Fly) inject PORT; the healthcheck follows it.
HEALTHCHECK --interval=30s --timeout=5s CMD python -c "import os,urllib.request;urllib.request.urlopen('http://127.0.0.1:%s/v1/health'%os.environ.get('PORT','8080'),timeout=4)"
CMD ["python", "backend/app.py"]
