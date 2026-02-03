FROM python:3.12-slim
WORKDIR /app
COPY scanner.py .
COPY config.json .
CMD ["python", "scanner.py"]