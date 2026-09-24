# riskrank image (R046): the CLI and the dashboard in one image.
#
#   docker compose up -d                      # ZAP + dashboard on http://localhost:8000
#   docker compose run --rm riskrank scan ... # run a scan (see docker-compose.yml)
#
FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# Dependencies first, so code changes don't reinstall them.
COPY requirements.txt ./
RUN pip install -r requirements.txt

COPY pyproject.toml README.md LICENSE ./
COPY src ./src
COPY examples ./examples
RUN pip install --no-deps .

# Run as an unprivileged user. /data holds the SQLite database (a volume);
# /scans is the working directory, where --output/--report files are written.
RUN useradd --create-home --uid 10001 riskrank \
    && mkdir -p /data /scans \
    && chown riskrank:riskrank /data /scans
USER riskrank
WORKDIR /scans

ENV DATABASE_URL=sqlite:////data/riskrank.db \
    ZAP_API_URL=http://zap:8080 \
    DASHBOARD_HOST=0.0.0.0 \
    DASHBOARD_PORT=8000

VOLUME ["/data"]
EXPOSE 8000

ENTRYPOINT ["riskrank"]
CMD ["serve"]
