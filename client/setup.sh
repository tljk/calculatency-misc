USERNAME=$(whoami)
IPS="127.0.0.1"
TIMEOUT=10
FILEPATH="/home/$USERNAME/calculatency-misc/client"
make client
# add crontab to execute client every minute
(crontab -l | grep -v "$FILEPATH/client -ips $IPS -timeout 10" ; echo "* * * * * /bin/bash -c \"$FILEPATH/client -ips $IPS -timeout $TIMEOUT\" >> $FILEPATH/log.txt 2>&1 ") | crontab -
crontab -l