FROM python:3.13-slim

# Define build arguments
ARG USER_ID=1064
ARG GROUP_ID=1064
ARG USER_NAME=l64user
ARG GROUP_NAME=l64group

# Create group and user with the specified IDs
RUN groupadd -g ${GROUP_ID} ${GROUP_NAME} && \
    useradd -m -u ${USER_ID} -g ${GROUP_NAME} ${USER_NAME}

# Set working directory
WORKDIR /home/${USER_NAME}

# Copy the requirements file into the container at the working directory
COPY --chown=${USER_NAME}:${GROUP_NAME} requirements.txt .

# Copy the FastAPI application (no longer single-file: policy_store.py holds the
# in-memory routing table, routes_loader.py loads the generated routes manifests
# + static-route policies, authz_edge.py is the Cerbos PDP HTTP client). A
# default static_routes.yaml ships as a fallback; the chart mounts ConfigMaps
# over routes/ and static_routes.yaml.
COPY --chown=${USER_NAME}:${GROUP_NAME} traefik_authproxy.py policy_store.py routes_loader.py authz_edge.py static_routes.yaml ./

# Install any needed packages specified in requirements.txt
RUN python -m pip install --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Observability runtime (infrastructure-owned; auto-instrumentation activated by
# entrypoint.sh only when OTEL_EXPORTER_OTLP_ENDPOINT is set). Same image, both modes.
COPY --chown=${USER_NAME}:${GROUP_NAME} requirements-otel.txt .
RUN pip install --no-cache-dir -r requirements-otel.txt
COPY --chown=${USER_NAME}:${GROUP_NAME} entrypoint.sh .
RUN chmod 755 entrypoint.sh

# Make port 8081 available outside this container
EXPOSE 8081

# Health check (python stdlib — slim ships neither wget nor curl)
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD python -c "import urllib.request;urllib.request.urlopen('http://localhost:8081/health', timeout=4)" || exit 1

# Set user context
USER ${USER_NAME}

# entrypoint.sh enables OTel auto-instrumentation iff OTEL_EXPORTER_OTLP_ENDPOINT is set
ENTRYPOINT ["./entrypoint.sh"]

# Run the FastAPI application using Uvicorn
CMD ["uvicorn", "traefik_authproxy:app", "--host", "0.0.0.0", "--port", "8081"]
