FROM python:3.9

# Set working directory
WORKDIR /app

# Copy client files
COPY generate.py .

# Install dependencies
RUN pip install --no-cache-dir numpy

# Run the client script
CMD ["python", "generate.py"]
