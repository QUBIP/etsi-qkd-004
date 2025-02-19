FROM python:3.9

# Set working directory
WORKDIR /app

# Copy server files
COPY server.py . 

# Expose the server port
EXPOSE 25575

# Run the server script
CMD ["python", "server.py"]
