FROM python:3.11-slim

WORKDIR /app

# Create data dir for SQLite DB (will be mounted as a volume)
RUN mkdir -p /app/data

COPY server.py .
COPY tracker.html .
COPY login.html .

EXPOSE 8090

CMD ["python", "-u", "server.py"]
