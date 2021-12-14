sudo apt update　-y
sudo apt-get install binutils -y
sudo apt-get install xxd -y
sudo apt-get install file -y
sudo apt-get install figlet -y
cd /usr/local/bin

wget "https://github.com/crum7/Stella/raw/main/stella_2.0"
mv stella2.0 stella
chmod 777 stella

wget "https://github.com/fireeye/flare-floss/releases/download/v1.7.0/floss-v1.7.0-linux.zip"
unzip floss-v1.7.0-linux.zip

chmod 777 floss
rm floss-v1.7.0-linux.zip
rm install.sh
