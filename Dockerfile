# Use the official Python image with slim variant
FROM python:3.12-slim AS base

# Set the working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    libpq-dev \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install Poetry
RUN curl -sSL https://install.python-poetry.org | python3 -

# Add Poetry to PATH
ENV PATH="/root/.local/bin:$PATH"

# Copy only Poetry config files to leverage Docker layer caching
COPY pyproject.toml poetry.lock /app/

# Install dependencies (without dev dependencies)
RUN poetry install --only main --no-interaction --no-root

# Copy the entire application to the working directory
COPY . /app

# Expose port 5000 for the FastAPI app
EXPOSE 5000

# Define the command to run the application
CMD ["poetry", "run", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "5000"]
