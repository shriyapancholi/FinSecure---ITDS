# ---------- Stage 1: base environment ----------
FROM python:3.11-slim AS base

WORKDIR /app

# Copy dependency lists
COPY requirements.txt ./

# Install dependencies system-wide
RUN pip install --no-cache-dir -r requirements.txt gunicorn

# Copy app source
COPY . .

# Expose the app port (for docker run / compose)
EXPOSE 5000

# Environment vars (override in compose)
ENV FLASK_ENV=production \
    SENTINEL_SECRET_KEY=change-me-before-deploy \
    RATELIMIT_STORAGE_URI=memory://

# Gunicorn command: 4 workers, bind to 0.0.0.0:5000
CMD ["gunicorn", "-w", "4", "-b", "0.0.0.0:5000", "app:app"]