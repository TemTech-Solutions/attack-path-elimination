FROM python:3.13-slim
WORKDIR /app
COPY requirements.txt .
RUN python -m pip install --upgrade pip \
 && python -m pip install --no-cache-dir -r requirements.txt
COPY . .
EXPOSE 8080
CMD ["python", "-m", "pathfinder", "serve", "--host", "0.0.0.0", "--port", "8080"]
