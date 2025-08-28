FROM python:3.9

RUN apt-get update && apt-get install -y \
    iproute2 \
    iptables \
    iputils-ping \
    tcpdump \
    traceroute \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy client files
COPY generate.py .

# Run the client script
CMD ["python", "generate.py"]
