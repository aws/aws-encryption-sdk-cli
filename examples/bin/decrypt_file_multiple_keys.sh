#!/bin/bash

# Basic example invocation of the AWS Encryption CLI to decrypt a file that was encrypted with multiple
# master keys
# See full docs for more details:
#  https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/crypto-cli-examples.html

# Usage: decrypt_file_multiple_keys.sh $INPUT_FILE $CMK_ARN_1 $CMK_ARN_2 $OUTPUT_DIRECTORY

aws-encryption-cli --decrypt \
                   --input $1 \
                   --wrapping-keys key=$2 key=$3 \
                   --commitment-policy require-encrypt-require-decrypt \
                   --encryption-context purpose=test \
                   --suppress-metadata \
                   --max-encrypted-data-keys 2 \
                   --buffer \
                   --output $4
