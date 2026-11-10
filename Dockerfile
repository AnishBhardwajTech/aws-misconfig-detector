FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY misconfig ./misconfig
RUN useradd --create-home scanner && mkdir -p /var/log/misconfig && chown scanner /var/log/misconfig
USER scanner
ENV SCAN_LOG_FILE=/var/log/misconfig/scan.jsonl
EXPOSE 5000
CMD ["gunicorn", "-b", "0.0.0.0:5000", "-w", "1", "--threads", "4", "misconfig.wsgi:app"]
