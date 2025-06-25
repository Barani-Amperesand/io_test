# Use an older, stable version of Ubuntu for broad compatibility
FROM ubuntu:20.04

# Avoid interactive prompts during package installation
ENV DEBIAN_FRONTEND=noninteractive

# Install all necessary system dependencies
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    protobuf-compiler \
    && rm -rf /var/lib/apt/lists/*

# Set the working directory inside the container
WORKDIR /app

# Copy your project files into the container's /app directory
COPY . .

# Install Python dependencies
RUN pip3 install --no-cache-dir pyinstaller pyserial requests protobuf

# Build the single-file executable
RUN pyinstaller --onefile bitwise.py

# No CMD or ENTRYPOINT is needed, as we just want to build and extract


# sudo docker build -t bitwise .
# sudo docker create --name dummy_container bitwise
# sudo docker cp dummy_container:/app/dist ./
# sudo docker rm dummy_container
# sudo chown $(whoami):$(whoami) ./dist/bitwise 