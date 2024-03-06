#!/bin/bash
# dnf install -y openssh-clients && scp omoris@192.168.0.122:/home/omoris/Work/Projects/pkcs11-provider-omoris/tests/runtest.sh /tmp
set -xeo pipefail

PIN="123456"

PKCS11_DEBUG_FILE="/tmp/pkcs11.log"

function install_dependencies() {
	dnf install -y --releasever=40 --skip-broken \
        p11-kit httpd mod_ssl openssl softhsm gnutls-utils \
	    gcc g++ git cmake libcmocka libcmocka-devel \
	    autoconf automake autoconf-archive libtool softhsm nss-tools \
	    gnutls-utils p11-kit p11-kit-devel p11-kit-server opensc \
	    softhsm-devel socket_wrapper nss_wrapper uid_wrapper \
	    pam_wrapper priv_wrapper openssh-server zlib-devel
	dnf update -y --releasever=40 --skip-broken openssl
}

function softhsm_token_setup() {

    # Generate CA and server keys.
    mkdir ca server
    openssl req -x509 -sha256 -newkey rsa:2048 -keyout ca/key.pem -out ca/cert.pem -noenc -batch
    openssl req -newkey rsa:2048 -keyout server/key.pem -out server/csr.pem -noenc --batch -subj '/CN=localhost'
    openssl x509 -req -CA ca/cert.pem -CAkey ca/key.pem -in server/csr.pem -out server/cert.pem -CAcreateserial
    chown -R apache:apache ca server

    # Setup the token.
    usermod -a -G ods apache
    runuser -u apache -- \
        softhsm2-util --init-token --free --label softtoken --pin $PIN --so-pin $PIN
    TOKENURL=$(runuser -u apache -- \
        p11tool --list-tokens | grep "URL:.*token=softtoken" |awk '{ print $NF }')
    runuser -u apache -- \
        p11tool --write --load-privkey server/key.pem --label httpd --id=%01 --login --set-pin $PIN $TOKENURL
    runuser -u apache -- \
        p11tool --write --load-certificate server/cert.pem --label httpd --id=%01 --login --set-pin $PIN $TOKENURL

    # Output of tokens and their certificates and keys (for debugging).
    p11tool --list-tokens 
    p11tool --login --set-pin $PIN --list-keys $TOKENURL 
    p11tool --list-all-certs $TOKENURL
}

function pkcs11_provider_setup() {
    if [ "$GITHUB_ACTIONS" == "true" ]; then
        echo "Skipped"
    else
        git clone https://github.com/latchset/pkcs11-provider.git
        pushd pkcs11-provider
        autoreconf -fiv
        ./configure --libdir=/usr/lib64
        make
        make install
        popd
    fi
    if [ -e $PKCS11_DEBUG_FILE ]; then
        rm -f $PKCS11_DEBUG_FILE
    fi
    export PKCS11_PROVIDER_DEBUG=file:$PKCS11_DEBUG_FILE
}

function openssl_setup() {

    # Add and activate pkcs11 provider section in openssl configuration.
    sed    -e 's|\(default = default_sect\)|\1\npkcs11 = pkcs11_sect\n|' \
           -e 's|\(\[default_sect\]\)|\[pkcs11_sect\]\n\1|' \
           -e 's|\(\[default_sect\]\)|module = /usr/lib64/ossl-modules/pkcs11.so\n\1|' \
           -e 's|\(\[default_sect\]\)|#pkcs11-module-path = /usr/lib64/pkcs11/libsofthsm2.so\n\1|' \
           -e 's|\(\[default_sect\]\)|#pkcs11-module-load-behavior = early\n\1|' \
           -e 's|\(\[default_sect\]\)|pkcs11-module-token-pin = file:/tmp/pin.txt\n\1|' \
           -e 's|\(\[default_sect\]\)|activate = 1\n\n\1|' \
        /etc/pki/tls/openssl.cnf >/tmp/openssl.cnf

    # Print openssl.cnf (for debugging).
    cat /etc/pki/tls/openssl.cnf
}

function httpd_setup() {

    # Setup httpd mod_ssl to use token keys.
    TOKENURL=$(runuser -u apache -- \
        p11tool --list-tokens | grep "URL:.*token=softtoken" | awk '{ print $NF }')
    KEYURL="$(runuser -u apache -- \
        p11tool --login --set-pin $PIN --list-keys $TOKENURL \
        | grep 'URL:.*object=httpd;type=private' \
        | awk '{ print $NF }')?pin-value=$PIN"
    CERTURL=$(runuser -u apache -- \
        p11tool --list-all-certs $TOKENURL | grep "URL:.*object=httpd;type=cert" | awk '{ print $NF }')
    sed -i -e "/SSLCryptoDevice/d" \
           -e "s/^SSLCertificateFile.*\$/SSLCertificateFile \"$CERTURL\"/" \
           -e "s/^SSLCertificateKeyFile.*\$/SSLCertificateKeyFile \"$KEYURL\"/" \
           /etc/httpd/conf.d/ssl.conf

    eval $(p11-kit server --provider /usr/lib64/pkcs11/libsofthsm2.so "$TOKENURL")
    export PKCS11_PROVIDER_MODULE=/usr/lib64/pkcs11/p11-kit-client.so
    #export PKCS11_PROVIDER_MODULE=/usr/lib64/pkcs11/libsofthsm2.so
    sleep 3
    # List URLs and mod_ssl configuration (for debugging).
    echo "TOKENURL=$TOKENURL"
    echo "KEYURL=$KEYURL"
    echo "CERTURL=$CERTURL"
    cat /etc/httpd/conf.d/ssl.conf

}

function httpd_test() {
    
    # Start the server.
    echo "$PIN" >/tmp/pin.txt
    OPENSSL_CONF=/tmp/openssl.cnf openssl pkey -in "$TOKENURL" -pubin -pubout -text 
    OPENSSL_CONF=/tmp/openssl.cnf httpd -DFOREGROUND &
    sleep 3
    if ! pgrep httpd; then
        cat /var/log/httpd/error_log
        cat /var/log/httpd/ssl_error_log
        cat $PKCS11_DEBUG_FILE
        return
    fi 

    # Query the server.
    #PS1="TEST> " bash
    sleep 10 && curl -v -sS --cacert ca/cert.pem https://localhost

    if [ $? -ne 0 ]; then
        cat /var/log/httpd/error_log
        cat /var/log/httpd/ssl_error_log
        cat $PKCS11_DEBUG_FILE
        return
    fi

    cat $PKCS11_DEBUG_FILE
    echo "Test passed."
}

# Setup.
#install_dependencies
softhsm_token_setup
pkcs11_provider_setup
openssl_setup
httpd_setup

# Test.
httpd_test
