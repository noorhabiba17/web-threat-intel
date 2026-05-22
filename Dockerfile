# ─── Build stage ───
FROM python:3.12-slim AS builder

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt


# ─── Runtime stage ───
FROM python:3.12-slim

WORKDIR /app

# Copy installed packages from builder
COPY --from=builder /root/.local /root/.local
ENV PATH=/root/.local/bin:$PATH

# Copy application code
COPY . .

# Create instance directory for SQLite DB
RUN mkdir -p /app/instance

EXPOSE 5000

CMD ["python", "app.py"]
