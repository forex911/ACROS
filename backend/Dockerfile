# Full image includes libmagic, gcc, and build tools — no apt-get needed
FROM python:3.11-bookworm

# Create a non-root user for security and install Node.js
RUN apt-get update && apt-get install -y nodejs npm && rm -rf /var/lib/apt/lists/* && \
    groupadd -g 1001 appgroup && \
    useradd -u 1001 -g appgroup -s /bin/bash -m appuser

WORKDIR /sandbox

# Install Python dependencies
# 1. Install CPU-only PyTorch first (~200MB vs ~4GB with CUDA)
# 2. Swap python-magic-bin (Windows-only) with python-magic (Linux)
# 3. Install remaining dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir torch==2.6.0+cpu --index-url https://download.pytorch.org/whl/cpu && \
    sed -i '/^torch==/d; /^triton==/d; s/python-magic-bin==0.4.14/python-magic==0.4.27/' requirements.txt && \
    pip install --no-cache-dir -r requirements.txt


# Copy application source
COPY --chown=appuser:appgroup . .

# Create upload/report dirs with correct ownership
RUN mkdir -p /tmp/aegis_uploads /tmp/aegis_reports && \
    chown -R appuser:appgroup /tmp/aegis_uploads /tmp/aegis_reports

# Set non-root user
USER appuser

EXPOSE 8000

# Start Uvicorn
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]