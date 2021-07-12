#!/bin/bash

# Basic example invocation of the AWS Encryption CLI to encrypt a file with multiple master keys
# See full docs for more details:
#  https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/crypto-cli-examples.html

# Usage: encrypt_file_multiple_keys.sh $INPUT_FILE $CMK_ARN_1 $CMK_ARN_2 $OUTPUT_DIRECTORY

aws-encryption-cli --encrypt \
                   --input $1 \
                   --wrapping-keys key=$2 key=$3 \
                   --suppress-metadata \
                   --encryption-context purpose=test \
                   --commitment-policy require-encrypt-require-decrypt \
                   --output $4
