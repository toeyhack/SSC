# Architecture

High level architecture:

Browser -> Frontend (React/Vite) -> FastAPI -> PostgreSQL + Redis -> Celery workers (scanner)

See docs/IMPLEMENTATION_STATUS.md for the current implemented components.
