FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1

RUN useradd --create-home --shell /bin/bash appuser

WORKDIR /srv

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY . /srv
RUN chown -R appuser:appuser /srv

USER appuser

EXPOSE 6000

CMD ["./worker-entrypoint.sh"]
