FROM python:3.11-slim

WORKDIR /app
ENV PYTHONUNBUFFERED=1 PORT=8000

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8000
# 必须 -w 1：多 worker 会每个进程各跑一个推送线程，同一条消息推 N 次
CMD gunicorn -w 1 --threads 16 --timeout 120 -b 0.0.0.0:$PORT app:app
