FROM python:3.9

# Set working directory
WORKDIR /app

# Debug tools: ping, netcat (nc), ip (for ip a), and traceroute
# RUN apt-get update && apt-get install -y \
#     iputils-ping \
#     netcat-openbsd \
#     iproute2 \
#     traceroute \
#     && rm -rf /var/lib/apt/lists/*

# Copy client files
COPY generate.py .

# Run the client script
CMD ["python", "generate.py"]
