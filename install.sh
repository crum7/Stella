sudo apt update　-y
sudo apt-get install binutils -y
sudo apt-get install xxd -y
sudo apt-get install file -y
sudo apt-get install boxes -y
sudo apt-get install figlet -y

wget "https://github.com/crum7/Stella/raw/main/stella01"
mv stella01 stella
chmod 777 stella

wget "https://github.com/fireeye/flare-floss/releases/download/v1.7.0/floss-v1.7.0-linux.zip"
unzip floss-v1.7.0-linux.zip
wget "https://github.com/crum7/stella/raw/main/stellaf01"
mv stellaf01 stellaf
chmod 777 floss
chmod 777 stellaf
rm floss-v1.7.0-linux.zip
rm install.sh
