#!/bin/bash
OPENSSL_V110="${HOME}/local/bin/openssl.sh"
PUB_WRAPPING_KEY="${HOME}/wrapping-key.pem"
TARGET_KEY=$1
BASE_DIR="${HOME}/wrap_tmp"
mkdir -m 700 -p ${BASE_DIR}
TEMP_AES_KEY="${BASE_DIR}/temp_aes_key.bin"
TEMP_AES_KEY_WRAPPED="${BASE_DIR}/temp_aes_key_wrapped.bin"
TARGET_KEY_WRAPPED="${BASE_DIR}/target_key_wrapped.bin"
RSA_AES_WRAPPED_KEY=/tmp/wrapped-target-key.bin
mkdir -m u+wx -p $(dirname ${RSA_AES_WRAPPED_KEY})
echo "OPENSSL_V110: " ${OPENSSL_V110}; \
echo "PUB_WRAPPING_KEY: " ${PUB_WRAPPING_KEY}; \
echo "TARGET_KEY: " ${TARGET_KEY}; \
echo "BASE_DIR: " ${BASE_DIR}; \
echo "TEMP_AES_KEY: " ${TEMP_AES_KEY}; \
echo "TEMP_AES_KEY_WRAPPED: " ${TEMP_AES_KEY_WRAPPED}; \
echo "TARGET_KEY_WRAPPED: " ${TARGET_KEY_WRAPPED}; \
echo "RSA_AES_WRAPPED_KEY: " ${RSA_AES_WRAPPED_KEY}

"${OPENSSL_V110}" rand -out "${TEMP_AES_KEY}" 32

"${OPENSSL_V110}" rsautl \
   -encrypt \
   -pubin \
   -inkey "${PUB_WRAPPING_KEY}" \
   -in "${TEMP_AES_KEY}" \
   -out "${TEMP_AES_KEY_WRAPPED}" \
   -oaep


   "${OPENSSL_V110}" enc \
  -id-aes256-wrap-pad \
  -iv A65959A6 \
  -K $( hexdump -v -e '/1 "%02x"' < "${TEMP_AES_KEY}" ) \
  -in "${TARGET_KEY}" \
  -out "${TARGET_KEY_WRAPPED}"


  cat "${TEMP_AES_KEY_WRAPPED}" "${TARGET_KEY_WRAPPED}" > "${RSA_AES_WRAPPED_KEY}"
  rm ${BASE_DIR}/*