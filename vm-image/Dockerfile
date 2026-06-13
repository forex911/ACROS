FROM alpine:latest

# Install Python 3 and basic utilities
RUN apk add --no-cache python3 py3-pip openrc util-linux e2fsprogs

# Setup directory for the agent
RUN mkdir -p /agent /sandbox

# Copy the agent and boot script
COPY analysis_agent.py /agent/
COPY install_agent.sh /agent/

# Make scripts executable
RUN chmod +x /agent/analysis_agent.py
RUN chmod +x /agent/install_agent.sh

# Run the installation script to setup OpenRC service
RUN /agent/install_agent.sh

# Set the default shell
CMD ["/sbin/init"]
