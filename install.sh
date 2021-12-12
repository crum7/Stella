sudo apt-get install binutils
sudo apt-get install xxd
sudo apt-get install file
sudo apt update

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
