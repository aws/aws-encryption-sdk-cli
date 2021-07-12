#!/bin/bash

# Basic example invocation of the AWS Encryption CLI to decrypt input from the command line
# See full docs for more details:
#  https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/crypto-cli-examples.html

# Usage: decrypt_command_line.sh $PLAINTEXT

echo "$1" | aws-encryption-cli --decrypt \
                               --suppress-metadata \
                               --input - \
                               --output - \
                               --decode \
                               --buffer \
                               --wrapping-keys discovery=true
