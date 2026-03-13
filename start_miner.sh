#!/bin/bash

# --- 1. Configuration & Variables ---
TARGET="Release"
INSTALL_DIR="/root/seth_miner"
rm -rf $INSTALL_DIR
cp -rf ./mining_node $INSTALL_DIR
CONFIG_FILE="$INSTALL_DIR/conf/seth.conf"
CONFIG_TEMP="$INSTALL_DIR/conf/seth.conf_temp"
SERVICE_NAME="seth_miner"

# Check if argument 1 is provided
if [ -z "$1" ]; then
    echo "No private key provided. Generating a random 32-byte hex key..."
    # Generate 32 bytes of random data and convert to hex (64 characters)
    RAW_PRIVATE_KEY=$(openssl rand -hex 32)
    echo "Generated Private Key: $RAW_PRIVATE_KEY"
else
    RAW_PRIVATE_KEY="$1"
    echo "Giving Private Key: $RAW_PRIVATE_KEY"
fi

echo "Starting deployment for $SERVICE_NAME..."

# --- 2. Build and Environment Setup ---
bash build.sh a $TARGET
# --- 3. Network Discovery ---
if command -v hostname > /dev/null; then
    LOCAL_IP=$(hostname -I | awk '{print $1}')
else
    LOCAL_IP=$(ip addr show | grep -w inet | grep -v 127.0.0.1 | awk '{print $2}' | cut -d/ -f1 | head -n 1)
fi

PUBLIC_IP=$(curl -s --connect-timeout 5 ifconfig.me || curl -s --connect-timeout 5 ipinfo.io/ip)

if [ -z "$LOCAL_IP" ] || [ -z "$PUBLIC_IP" ]; then
    echo "Error: Failed to retrieve network IP addresses."
    exit 1
fi

# --- 4. Encrypt Private Key ---
ENCRYPT_CMD="./cbuild_$TARGET/seth"
mkdir -p $INSTALL_DIR/bin $INSTALL_DIR/log
cp -rf $ENCRYPT_CMD $INSTALL_DIR/bin/seth


OUTPUT=$($ENCRYPT_CMD -K "${RAW_PRIVATE_KEY}")
PRIVATE_KEY=""
if [ $? -eq 0 ] && [ -n "$OUTPUT" ]; then
    IFS=":" read -r PRIVATE_KEY WALLET_ADDRESS <<< "$OUTPUT"
    echo "Encrypted Private Key: $PRIVATE_KEY"
    echo "Wallet Address: $WALLET_ADDRESS"
else
    echo "Error: Failed to get key and address."
    exit 1
fi

if [ $? -ne 0 ]; then
    echo "Encryption failed! Details: $PRIVATE_KEY"
    exit 1
fi

# --- 5. Install Files & Update Config ---
cp "$ENCRYPT_CMD" "$INSTALL_DIR/bin/seth"
if [ -f "$CONFIG_TEMP" ]; then
    cp -rf "$CONFIG_TEMP" "$CONFIG_FILE"
    sed -i "s@REPLACE_PRIVATE_KEY@$PRIVATE_KEY@g" "$CONFIG_FILE"
    sed -i "s@REPLACE_LOCAL_IP@$LOCAL_IP@g" "$CONFIG_FILE"
    sed -i "s@REPLACE_PUBLIC_IP@$PUBLIC_IP@g" "$CONFIG_FILE"
else
    echo "Warning: Template $CONFIG_TEMP not found. Skipping config update."
fi

# --- 6. Create Systemd Service ---
echo "Creating systemd service..."
cat <<EOF > /etc/systemd/system/$SERVICE_NAME.service
[Unit]
Description=Seth Mining Node
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$INSTALL_DIR
ExecStart=$INSTALL_DIR/bin/seth -f 0 -g 0
Restart=always
RestartSec=5
StandardOutput=append:$INSTALL_DIR/log/stdout.log
StandardError=append:$INSTALL_DIR/log/stderr.log

[Install]
WantedBy=multi-user.target
EOF

# --- 7. Start Service ---
systemctl daemon-reload
systemctl enable $SERVICE_NAME
systemctl restart $SERVICE_NAME

echo "------------------------------------------------"
echo "Deployment Complete!"
echo "Service: $SERVICE_NAME"
echo "Status: $(systemctl is-active $SERVICE_NAME)"
echo "Local IP: $LOCAL_IP"
echo "Public IP: $PUBLIC_IP"
echo "Logs: tail -f $INSTALL_DIR/log/stdout.log"
echo "------------------------------------------------"