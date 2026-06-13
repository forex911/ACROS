#!/bin/sh

# This script sets up an OpenRC service to run the analysis agent on boot.

cat << 'EOF' > /etc/init.d/analysis-agent
#!/sbin/openrc-run

name="Sentinel Analysis Agent"
command="/usr/bin/python3"
command_args="/agent/analysis_agent.py"
command_background="true"
pidfile="/run/${RC_SVCNAME}.pid"
output_log="/var/log/analysis_agent.log"
error_log="/var/log/analysis_agent.err"

depend() {
    need localmount
}

start_pre() {
    mkdir -p /sandbox
}
EOF

chmod +x /etc/init.d/analysis-agent
rc-update add analysis-agent default

# Enable serial console login without password for debugging (optional)
sed -i 's/^root:.*$/root::14871::::::/' /etc/shadow
echo "ttyS0::respawn:/sbin/getty -L ttyS0 115200 vt100" >> /etc/inittab
