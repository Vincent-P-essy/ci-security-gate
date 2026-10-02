FROM python:3.12-slim
WORKDIR /app
USER 10001
CMD ["python", "--version"]
