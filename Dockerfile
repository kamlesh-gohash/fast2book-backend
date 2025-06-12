FROM python:3.13-slim AS base

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

# Build arguments
ARG DATABASE_NAME
ARG DATABASE_URL
ARG DEBUG
ARG GOOGLE_CLIENT_ID
ARG GOOGLE_CLIENT_SECRET
ARG SECRET_KEY
ARG AWS_S3_BUCKET_NAME
ARG EMAIL_HOST
ARG EMAIL_PASSWORD
ARG EMAIL_PORT
ARG EMAIL_USER
ARG FRONT_URL
ARG GOOGLE_REDIRECT_URI
ARG PORT
ARG RAZOR_PAY_KEY_ID
ARG RAZOR_PAY_KEY_SECRET
ARG AWS_S3_REGION
ARG PROJECT_ID
ARG PRIVATE_KEY_ID
ARG PRIVATE_KEY
ARG CLIENT_EMAIL
ARG CLIENT_ID
ARG AUTH_URI
ARG TOKEN_URI
ARG AUTH_PROVIDER_X509_CERT_URL
ARG CLIENT_X509_CERT_URL
ARG UNIVERSE_DOMAIN
ARG TYPE
ARG APPLE_CLIENT_ID
ARG APPLE_TEAM_ID
ARG APPLE_KEY_ID


# Pass build arguments to environment variables
ENV DATABASE_NAME=$DATABASE_NAME \
    DATABASE_URL=$DATABASE_URL \
    DEBUG=$DEBUG \
    GOOGLE_CLIENT_ID=$GOOGLE_CLIENT_ID \
    GOOGLE_CLIENT_SECRET=$GOOGLE_CLIENT_SECRET \
    SECRET_KEY=$SECRET_KEY \
    AWS_S3_BUCKET_NAME=$AWS_S3_BUCKET_NAME \
    EMAIL_HOST=$EMAIL_HOST \
    EMAIL_PASSWORD=$EMAIL_PASSWORD \
    EMAIL_PORT=$EMAIL_PORT \
    EMAIL_USER=$EMAIL_USER \
    FRONT_URL=$FRONT_URL \
    GOOGLE_REDIRECT_URI=$GOOGLE_REDIRECT_URI \
    RAZOR_PAY_KEY_ID=$RAZOR_PAY_KEY_ID \
    RAZOR_PAY_KEY_SECRET=$RAZOR_PAY_KEY_SECRET \
    AWS_S3_REGION=$AWS_S3_REGION \
    PORT=$PORT \
    PROJECT_ID=$PROJECT_ID \
    PRIVATE_KEY_ID=$PRIVATE_KEY_ID \
    PRIVATE_KEY=$PRIVATE_KEY \
    CLIENT_EMAIL=$CLIENT_EMAIL \
    CLIENT_ID=$CLIENT_ID \
    AUTH_URI=$AUTH_URI \
    TOKEN_URI=$TOKEN_URI \
    AUTH_PROVIDER_X509_CERT_URL=$AUTH_PROVIDER_X509_CERT_URL \
    CLIENT_X509_CERT_URL=$CLIENT_X509_CERT_URL \
    UNIVERSE_DOMAIN=$UNIVERSE_DOMAIN \
    TYPE=$TYPE \
    APPLE_CLIENT_ID=$APPLE_CLIENT_ID \
    APPLE_TEAM_ID=$APPLE_TEAM_ID \
    APPLE_KEY_ID=$APPLE_KEY_ID

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
