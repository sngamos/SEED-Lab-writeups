sed -i '50i\unique_subject = no' /usr/lib/ssl/openssl.conf
sudo apt-get install libssl-dev
sudo apt-get install bless
mkdir PKI
cd PKI
mkdir demoCA
ln -s /usr/lib/ssl/openssl.cnf openssl.cnf
cd demoCA/
mkdir certs
mkdir crl
touch index.txt
mkdir newcerts
echo "1234" > serial
cd ..
