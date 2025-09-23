FROM python:3.9-slim

# Ensure Python output is flushed and no .pyc files are written
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Expose the port the app runs on
EXPOSE 5000

# Command to run the application
CMD ["python", "-u", "app.py"]
