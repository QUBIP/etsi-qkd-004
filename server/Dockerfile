FROM gcr.io/distroless/python3

# Set working directory
WORKDIR /app

# Copy server files
COPY server.py . 

# Expose the server port
EXPOSE 25575

# Run the server script
CMD ["server.py"]
