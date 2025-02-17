FROM python:3.9

# Set working directory
WORKDIR /app

# Install pytest
RUN pip install pytest

# Copy client files
COPY tests/tests.py .
COPY client/client.py .

# Run the client script
CMD ["pytest", "tests.py"]