#!/bin/bash

# Basic example invocation of the AWS Encryption CLI to decrypt all files in a directory
# See full docs for more details:
#  https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/crypto-cli-examples.html

# Usage: decrypt_directory.sh $INPUT_DIRECTORY $CMK_ARN $OUTPUT_DIRECTORY

aws-encryption-cli --decrypt \
                   --input $1 --recursive \
                   --wrapping-keys key=$2 \
                   --commitment-policy require-encrypt-require-decrypt \
                   --encryption-context purpose=test \
                   --suppress-metadata \
                   --max-encrypted-data-keys 1 \
                   --buffer \
                   --output $3
