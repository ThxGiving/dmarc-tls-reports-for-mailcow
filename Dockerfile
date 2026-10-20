FROM python:3.14-alpine
RUN apk add --no-cache tzdata
WORKDIR /app
COPY run.py ./
COPY collector ./collector
COPY web ./web
COPY lang ./lang
COPY nginx ./nginx
ARG APP_VERSION=dev
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 APP_VERSION=${APP_VERSION}
LABEL org.opencontainers.image.source="https://github.com/ThxGiving/dmarc-tls-reports-for-mailcow" \
      org.opencontainers.image.description="DMARC and TLS-RPT reports for mailcow, shown inside the mailcow UI" \
      org.opencontainers.image.licenses="MIT"
VOLUME /data
CMD ["python3", "/app/run.py"]
