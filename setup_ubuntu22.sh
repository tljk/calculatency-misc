sudo apt update
sudo apt -y install make git curl wget traceroute net-tools libpcap-dev build-essential openssl
snap install --classic go
snap install golangci-lint --classic
# chrome setup
wget https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb
sudo dpkg -i google-chrome-stable_current_amd64.deb
sudo apt install -f -y
rm google-chrome-stable_current_amd64.deb
google-chrome --version