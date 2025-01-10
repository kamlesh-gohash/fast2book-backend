# Stage 1: Build Stage
FROM python:3.12-slim AS build

# Set working directory
WORKDIR /app

# Install system dependencies required for Poetry and other Python packages
RUN apt-get update && apt-get install -y \
    build-essential \
    libpq-dev \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install Poetry (latest stable version)
RUN curl -sSL https://install.python-poetry.org | python3 -

# Add Poetry to PATH
ENV PATH="/root/.local/bin:$PATH"

# Copy Poetry configuration files to the container
COPY pyproject.toml poetry.lock /app/

# Install dependencies using Poetry
RUN poetry install --no-dev --no-interaction --no-root

# Formatting the code (this is optional, but can be done as part of the Docker build process)
RUN poetry run black .

# Running tests (also optional and would normally be done in CI)
RUN poetry run pytest --maxfail=1 --disable-warnings -q

# Stage 2: Runtime Stage
FROM python:3.12-slim

# Set working directory
WORKDIR /app

# Install runtime dependencies (just the necessary ones)
RUN apt-get update && apt-get install -y \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy the virtual environment from the build stage to this runtime stage
COPY --from=build /app /app

# Expose port 5000 (for FastAPI app with Uvicorn)
EXPOSE 5000

# Use a non-root user for security (create and switch to the non-root user)
RUN groupadd -r nonroot && useradd -r -g nonroot nonroot
USER nonroot

# Copy application files to the container
COPY ./app /app/

# Command to run the FastAPI app using Uvicorn
CMD ["poetry", "run", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "5000"]
