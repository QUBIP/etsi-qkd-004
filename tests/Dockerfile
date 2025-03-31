FROM python:3.9

# Set working directory
WORKDIR /app

# Install pytest
RUN pip install pytest

# Copy client files
COPY tests/tests.py .
COPY tests/test_key_manager.py .
COPY client/client.py .

# Copy KSID manager
RUN mkdir -p server/key_manager
COPY server/key_manager/key_manager.py server/key_manager/

# Run all tests
CMD ["pytest", "tests.py", "test_key_manager.py"]