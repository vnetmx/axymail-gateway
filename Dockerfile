FROM python:3.11-slim

WORKDIR /app

# Copy metadata first — leverages Docker layer cache
COPY pyproject.toml README.md ./

# Copy application source
COPY src/ ./src/

# Install the package and all dependencies (non-editable for production)
RUN pip install --no-cache-dir .

# Default data directory for SQLite
RUN mkdir -p /data

EXPOSE 3000

CMD ["uvicorn", "axymail_gateway.main:app", "--host", "0.0.0.0", "--port", "3000"]
