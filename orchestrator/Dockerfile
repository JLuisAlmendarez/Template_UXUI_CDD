FROM python:3.10-slim

WORKDIR /orchestrator

COPY . /orchestrator

RUN pip install --no-cache-dir -r requirements.txt

EXPOSE 5012

CMD ["python", "main.py"]
