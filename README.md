# ProgressJournal — Monthly Review

A personal AI-powered monthly work tracker. Connect GitHub, Jira, and Slack activity — get an AI-written digest of your wins, stalls, goals, and lessons learned.

## Stack
- Python stdlib HTTP server (no dependencies)
- Groq API (qwen3.8-27b) for AI summaries
- SQLite for user auth
- Docker + nginx on EC2

## Deploy
```bash
docker compose up --build -d
```

## Environment variables
Copy `.env.example` to `.env` and fill in:
```
GROQ_API_KEY=your_key_here
```
