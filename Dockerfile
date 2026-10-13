FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    SECURENOTES_ENV=production \
    DATABASE_URL=sqlite:////data/securenotes.db

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY securenotes ./securenotes
COPY wsgi.py .

# Run as an unprivileged user with a dedicated writable data directory.
RUN useradd --create-home --uid 10001 app && mkdir /data && chown app:app /data
USER app
VOLUME ["/data"]

EXPOSE 8000
# SECRET_KEY must be supplied at runtime: docker run -e SECRET_KEY=... ; the app refuses to start without it.
CMD ["gunicorn", "--bind", "0.0.0.0:8000", "--workers", "2", "--access-logfile", "-", "wsgi:app"]
