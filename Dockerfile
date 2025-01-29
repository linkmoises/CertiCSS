FROM python:3.9-slim

WORKDIR /app

COPY app.py .

RUN git rev-parse --short HEAD > version.txt

COPY requirements.txt .

RUN pip install -r requirements.txt

EXPOSE 5000

CMD ["python", "app.py"]