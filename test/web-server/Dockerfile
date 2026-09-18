FROM python:3.12-alpine AS builder

WORKDIR /build

COPY requirements.txt .

RUN pip install --no-cache-dir --prefix=/build/local -r requirements.txt

FROM python:3.12-alpine

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app/local/lib/python3.12/site-packages

WORKDIR /app

RUN addgroup -S flask && adduser -S flask -G flask

COPY --from=builder /build/local /app/local

COPY app.py .

COPY ./templates ./templates

RUN chown -R flask:flask /app && \
    chmod -R 550 /app

USER flask

EXPOSE 8080

CMD ["python", "app.py"]
