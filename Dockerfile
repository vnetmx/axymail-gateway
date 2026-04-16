FROM python:3.11-slim

WORKDIR /app

# Copy package metadata first — leverages Docker layer cache
COPY pyproject.toml .

# Copy application source
COPY src/ ./src/

# Install the package and all dependencies
RUN pip install --no-cache-dir -e .

# Default data directory for SQLite
RUN mkdir -p /data

EXPOSE 3000

CMD ["uvicorn", "axymail_gateway.main:app", "--host", "0.0.0.0", "--port", "3000"]
