SERVICENAME=webserver
SERVICEFILE=/etc/systemd/system/webserver.service
USERNAME=$(whoami)
FILEPATH="/home/$USERNAME/calculatency-misc/webserver"

make webserver
openssl req -nodes -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -sha256 -days 365 -subj "/C=US/ST=Oregon/L=Portland/O=Company Name/OU=Org/CN=192.168.1.3"
# create service
sudo bash -c "cat > $SERVICEFILE" <<EOL
[Unit]
Description=Web Server Service
After=network.target

[Service]
ExecStart=/bin/bash -c '$FILEPATH/webserver -cert $FILEPATH/cert.pem -key $FILEPATH/key.pem -path $FILEPATH/'
Restart=always
User=root
Group=root

[Install]
WantedBy=multi-user.target
EOL
sudo systemctl daemon-reload
sudo systemctl enable $SERVICENAME
sudo systemctl start $SERVICENAME
sudo systemctl status $SERVICENAME