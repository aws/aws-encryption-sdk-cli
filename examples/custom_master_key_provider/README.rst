###################################
Sample custom master key provider
###################################

This example shows how to write a custom master key provider, register it with
the AWS Encryption CLI, and use it with ``--wrapping-keys``.

The provider in `src/example_master_key_provider.py <./src/example_master_key_provider.py>`_
wraps data keys with AES-256-GCM using a raw 32-byte key read from a file. The value of ``key``
is the path to that file. It is for illustration only: a wrapping key stored unprotected on disk
is not suitable for production use.

The sample imports ``WrappingKey`` from ``aws_encryption_sdk.internal.crypto.wrapping_keys``.
That module is internal to the AWS Encryption SDK for Python and has no stability guarantee,
so check it again when you upgrade the SDK. The sample was run with ``aws-encryption-sdk`` 3.3.1
and Python 3.11; this CLI supports Python 3.10 to 3.12.

How it works
============

#. The provider is a subclass of ``aws_encryption_sdk.key_providers.raw.RawMasterKeyProvider``.
   It sets ``provider_id`` and implements ``_get_raw_key``, which returns the wrapping key
   for a key ID.
#. A factory function is the entry point. The CLI calls it with the extra ``name=value`` pairs
   of the ``--wrapping-keys`` group, collected into lists by name, plus a ``key_ids`` list,
   and must get back a master key provider instance. The CLI then calls ``add_master_key``
   once for each ``key`` value.
#. ``setup.py`` registers the factory in the ``aws_encryption_sdk_cli.master_key_providers``
   entry point group. The entry point name (``example-file-key``) is the value to use for
   ``provider=``.

Raise ``aws_encryption_sdk_cli.exceptions.BadUserArgumentError`` for invalid user input
so that the CLI prints the message instead of a stack trace.

Try it
======

.. code-block:: sh

   pip install aws-encryption-sdk-cli
   pip install ./examples/custom_master_key_provider

   head -c 32 /dev/urandom > wrapping.key
   echo "hello" > plaintext.txt
   mkdir encrypted decrypted

   aws-encryption-cli --encrypt \
                      --input plaintext.txt \
                      --wrapping-keys provider=example-file-key key=$PWD/wrapping.key \
                      --suppress-metadata \
                      --output encrypted

   aws-encryption-cli --decrypt \
                      --input encrypted/plaintext.txt.encrypted \
                      --wrapping-keys provider=example-file-key key=$PWD/wrapping.key \
                      --suppress-metadata \
                      --output decrypted

   cat decrypted/plaintext.txt.encrypted.decrypted

See `External Master Key Providers <../../README.rst#external-master-key-providers>`_ in the
main README for the entry point rules.
