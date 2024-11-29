FROM python:3.10-slim

WORKDIR /ml_models

COPY . /ml_models

RUN pip install --no-cache-dir -r requirements.txt

EXPOSE 5011

CMD ["python", "main.py"]
