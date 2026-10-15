# Deliberately insecure: CI asserts the policy REJECTS this file.
FROM python:latest
ADD https://example.com/app.tar.gz /app/
CMD ["python", "/app/app.py"]
