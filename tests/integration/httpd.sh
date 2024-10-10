#!/bin/bash -e
# Copyright (C) 2024 Ondrej Moris <omoris@redhat.com>
# SPDX-License-Identifier: Apache-2.0

if [ $# -ne 1 ]; then
    echo "Usage httpd.sh <tokentype>"
    exit 1
fi

# shellcheck disable=SC1091
source "../helpers.sh"

TOKENTYPE=$1

# Temporary dir and Token data dir
TMPPDIR="/tmp/httpd/${TOKENTYPE}"
TOKDIR="$TMPPDIR/tokens"
if [ -d "${TMPPDIR}" ]; then
    rm -fr "${TMPPDIR}"
fi
mkdir -p "${TMPPDIR}"
mkdir "${TOKDIR}"

PINVALUE="123456"
PINFILE="${TMPPDIR}/pinfile.txt"
echo ${PINVALUE} > "${PINFILE}"
PKCS11_DEBUG_FILE="${TMPPDIR}/pkcs11-httpd-test.log"
TEST_RESULT=1
MOD_SSL_CONF="/etc/httpd/conf.d/ssl.conf"

token_setup()
{
    title PARA "Token setup"

    if [ "${TOKENTYPE}" == "softhsm" ]; then
        # shellcheck disable=SC1091
        source "../softhsm-init.sh"
    elif [ "${TOKENTYPE}" == "softokn" ]; then
        # shellcheck disable=SC1091
        SHARED_EXT=".so" SOFTOKNPATH="/usr/lib64" source "../softokn-init.sh"
    elif [ "${TOKENTYPE}" == "kryoptic" ]; then
        # shellcheck disable=SC1091
        source "../kryoptic-init.sh"
    else
        echo "Unknown token type: $TOKENTYPE"
        exit 1
    fi
    export PKCS11_PROVIDER_MODULE=$P11LIB
    ${TOKENCONFIGVARS}

    ARGS=("--module=${P11LIB}" "--login" "--pin=${PINVALUE}" "--token-label=${TOKENLABEL}")
    mkdir "${TMPPDIR}/ca" "${TMPPDIR}/server"
    openssl req -x509 -sha256 -newkey rsa:2048 -noenc -batch -keyout "${TMPPDIR}/ca/key.pem" -out "${TMPPDIR}/ca/cert.pem"
    openssl req -newkey rsa:2048 -subj '/CN=localhost' -noenc -batch -keyout "${TMPPDIR}/server/key.pem" -out "${TMPPDIR}/server/csr.pem"
    openssl x509 -req -CA "${TMPPDIR}/ca/cert.pem" -CAkey "${TMPPDIR}/ca/key.pem" -in "${TMPPDIR}/server/csr.pem" -out "${TMPPDIR}/server/cert.pem" -CAcreateserial
    chown -R apache:apache "${TMPPDIR}/server"

    usermod -a -G ods apache

    pkcs11-tool "${ARGS[@]}" --write-object "${TMPPDIR}/server/key.pem" --type=privkey --id "0001"
    pkcs11-tool "${ARGS[@]}" --write-object "${TMPPDIR}/server/cert.pem" --type=cert --id "0002"

    title SECTION "List token content"
    pkcs11-tool "${ARGS[@]}" -O
    title ENDSECTION
}

pkcs11_provider_setup()
{
    title PARA "Get, compile and install pkcs11-provider"

    if [ -z "$PKCS11_MODULE" ]; then
        git clone \
            "${GIT_URL:-"https://github.com/latchset/pkcs11-provider.git"}" \
            "${TMPPDIR}"/pkcs11-provider
        pushd "${TMPPDIR}"/pkcs11-provider
        git checkout "${GIT_REF:-"main"}"
        meson setup -Dlibdir=/usr/lib64 builddir
        meson compile -C builddir
        meson install -C builddir
        popd
        export PKCS11_MODULE=/usr/lib64/ossl-modules/pkcs11.so
    else
        title LINE "Skipped"
    fi
}

openssl_setup()
{
    title PARA "OpenSSL setup"

    sed \
        -e "s|\(default = default_sect\)|\1\npkcs11 = pkcs11_sect\n|" \
        -e "s|\(\[default_sect\]\)|\[pkcs11_sect\]\n$TOKENOPTIONS\n\1|" \
        -e "s|\(\[default_sect\]\)|module = $PKCS11_MODULE\n\1|" \
        -e "s|\(\[default_sect\]\)|#pkcs11-module-load-behavior = early\n\1|" \
        -e "s|\(\[default_sect\]\)|activate = 1\n\1|" \
        -e "s|\(\[default_sect\]\)|pkcs11-module-token-pin = file:$PINFILE\n\n\1|" \
        /etc/pki/tls/openssl.cnf >"${TMPPDIR}"/openssl.cnf
}

httpd_setup()
{
    title PARAM "Httpd setup"

    cp -p $MOD_SSL_CONF{,.bck}
    sed -i -e "/^SSLCryptoDevice/d" \
           -e "s/^SSLCertificateFile.*\$/SSLCertificateFile \"pkcs11:type=cert\"/" \
           -e "s/^SSLCertificateKeyFile.*\$/SSLCertificateKeyFile \"pkcs11:type=private?pin-value=${PINVALUE}\"/" \
           $MOD_SSL_CONF
}

httpd_test()
{
    title PARA "Httpd test"

    (
        export OPENSSL_CONF=${WORKDIR}/openssl.cnf 
        export PKCS11_PROVIDER_DEBUG=file:${PKCS11_DEBUG_FILE}
        
        title SECTION "Test 1: Start httpd"
        httpd -DFOREGROUND &
        sleep 3
        if ! pgrep httpd >/dev/null; then
            echo "ERROR: Unable to start httpd!"
            exit 1
        fi
        title ENDSECTION

        title SECTION "Test 2: Curl connects to httpd over TLS"
        curl -v -sS --cacert "${TMPPDIR}/ca/cert.pem" https://localhost >/dev/null
        title ENDSECTION
    )
    title LINE "PASSED"
    TEST_RESULT=0
}

# shellcheck disable=SC2317
cleanup() 
{
    title PARA "Clean-up"

    if [ "$TEST_RESULT" -ne 0 ]; then
        for L in "${TMPPDIR}/openssl.cnf" "$PKCS11_DEBUG_FILE" "$MOD_SSL_CONF" "/var/log/httpd/ssl_error_log"; do
            if [ -e "$L" ]; then
                title SECTION "$L"
                cat "$L"
                title ENDSECTION
            fi
        done
    fi

    if pgrep httpd >/dev/null; then
        pkill httpd
    fi

    if [ -e "${MOD_SSL_CONF}".bck ]; then
        mv "${MOD_SSL_CONF}".bck "$MOD_SSL_CONF"
    fi
}

trap "cleanup" EXIT

# Setup.
token_setup
openssl_setup
httpd_setup

# Test.
httpd_test

exit $TEST_RESULT
