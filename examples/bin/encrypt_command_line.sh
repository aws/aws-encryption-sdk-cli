#!/bin/bash

# Basic example invocation of the AWS Encryption CLI to encrypt input from the command line
# See full docs for more details:
#  https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/crypto-cli-examples.html

# Usage: encrypt_command_line.sh $PLAINTEXT $CMK_ARN

echo "$1" | aws-encryption-cli --encrypt \
                               --suppress-metadata \
                               --input - \
                               --output - \
                               --encode \
                               --wrapping-keys key=$2
