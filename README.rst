######################
aws-encryption-sdk-cli
######################

.. image:: https://img.shields.io/pypi/v/aws-encryption-sdk-cli.svg
   :target: https://pypi.python.org/pypi/aws-encryption-sdk-cli
   :alt: Latest Version

.. image:: https://img.shields.io/pypi/pyversions/aws-encryption-sdk-cli.svg
   :target: https://pypi.python.org/pypi/aws-encryption-sdk-cli
   :alt: Supported Python Versions

.. image:: https://img.shields.io/badge/code_style-black-000000.svg
   :target: https://github.com/ambv/black
   :alt: Code style: black

.. image:: https://readthedocs.org/projects/aws-encryption-sdk-cli/badge/
   :target: https://aws-encryption-sdk-cli.readthedocs.io/en/stable/
   :alt: Documentation Status

.. image:: https://github.com/aws/aws-encryption-sdk-cli/workflows/tests/badge.svg
   :target: https://github.com/aws/aws-encryption-sdk-cli/actions?query=workflow%3Atests
   :alt: tests

.. image:: https://github.com/aws/aws-encryption-sdk-cli/workflows/static%20analysis/badge.svg
   :target: https://github.com/aws/aws-encryption-sdk-cli/actions?query=workflow%3A%22static+analysis%22
   :alt: static analysis


This command line tool can be used to encrypt and decrypt files and directories using the `AWS Encryption SDK`_.

The latest full documentation can be found at `Read the Docs`_.

Find us on `GitHub`_.

`Security issue notifications`_

See `Support Policy`_ for details on the current support status of all major versions of this library.

***************
Getting Started
***************

Required Prerequisites
======================

* Python 2.7+ or 3.4+

  **NOTE: 2.x is the last major version of this library that will
  support Python 2. Future major versions will begin to adopt changes
  known to break Python 2. Python 3.4 support will also be removed
  in future major versions; Python 3.5+ will be required.**
* aws-encryption-sdk >= 2.3.0

Installation
============

.. note::

   If you have not already installed `cryptography`_, you might need to install additional prerequisites as
   detailed in the `cryptography installation guide`_ for your operating system.

   .. code::

       $ pip install aws-encryption-sdk-cli

*****
Usage
*****

Input and Output
================

For the most part, the behavior of ``aws-encryption-cli`` in handling files is based on that
of GNU CLIs such as ``cp``.  A qualifier to this is that when encrypting a file, if a
directory is provided as the destination, rather than creating the source filename
in the destination directory, a suffix is appended to the destination filename. By
default the suffix is ``.encrypted`` when encrypting and ``.decrypted`` when decrypting,
but a custom suffix can be provided by the caller if desired.

If a destination file already exists, the contents will be overwritten.

.. table::

    +------------------------------+---------------------------------------+
    | **Allowed input/output       | **output**                            |
    | pairings**                   +------------+----------+---------------+
    |                              | **stdout** | **file** | **directory** |
    +-----------+------------------+------------+----------+---------------+
    | **input** |   **stdin**      | Y          | Y        |               |
    |           +------------------+------------+----------+---------------+
    |           |  **single file** | Y          | Y        | Y             |
    |           +------------------+------------+----------+---------------+
    |           | **pattern match**|            |          | Y             |
    |           +------------------+------------+----------+---------------+
    |           |   **directory**  |            |          | Y             |
    +-----------+------------------+------------+----------+---------------+

If the source includes a directory and the ``--recursive`` flag is set, the entire
tree of the source directory is replicated in the target directory.

Parameter Values
----------------
Some arguments accept additional parameter values.  These values must be provided in the
form of ``key=value`` as demonstrated below.

.. code-block:: sh

   --encryption-context key1=value1 key2=value2 "key 3=value with spaces"
   --master-keys provider=aws-kms key=$KEY_ID_1 key=$KEY_ID_2
   --caching capacity=3 max_age=80.0


Encryption Context
------------------

Encrypt
```````

The `encryption context`_ is an optional, but recommended, set of key-value pairs that contain
arbitrary nonsecret data. The encryption context can contain any data you choose, but it
typically consists of data that is useful in logging and tracking, such as data about the file
type, purpose, or ownership.

Parameters may be provided using `Parameter Values`_.

.. code-block:: sh

   --encryption-context key1=value1 key2=value2 "key 3=value with spaces"

Decrypt
```````

If an encryption context is provided on decrypt, it is instead used to require that the message
being decrypted was encrypted using an encryption context that matches the specified requirements.

If ``key=value`` elements are provided, the decryption will only continue if the encryption
context found in the encrypted message contains matching pairs.

.. code-block:: sh

   --encryption-context required_key=required_value classification=secret

If bare ``key`` elements are provided, the decryption will continue if those keys are found,
regardless of the values. ``key`` and ``key=value`` elements can be mixed.

.. code-block:: sh

   --encryption-context required_key classification=secret

.. warning::

   If encryption context requirements are not satisfied by the ciphertext message, the
   message will not be decrypted. One side effect of this is that if you chose to write
   the plaintext output to a file and that file already exists, it will be deleted when
   we stop the decryption.

Output Metadata
---------------
In addition to the actual output of the operation, there is metadata about the operation
that can be useful. This metadata includes some information about the operation as well as
the complete header data from the ciphertext message.

The metadata for each operation is written to the specified file as a single line containing
formatted JSON, so if a single command performs multiple file operations, a separate line
will be written for each operation. There are three operating modes:

* ``--metadata-output FILE`` : Writes the metadata output to ``FILE`` (can be ``-`` for stdout
  as long as main output is not stdout). Default behavior is to append the metadata entry to
  the end of ``FILE``.
* ``--overwrite-metadata`` : Force overwriting the contents of ``FILE`` with the new metadata.
* ``-S/--suppress-metadata`` : Output metadata is suppressed.

Metadata Contents
`````````````````
The metadata JSON contains the following fields:

* ``"mode"`` : ``"encrypt"``/``"decrypt"``/``"decrypt-unsigned"``
* ``"input"`` : Full path to input file (or ``"<stdin>"`` if stdin)
* ``"output"`` : Full path to output file (or ``"<stdout>"`` if stdout)
* ``"header"`` : JSON representation of `message header data`_
* ``"header_auth"`` : JSON representation of `message header authentication data`_ (only on decrypt)

Skipped Files
~~~~~~~~~~~~~
If encryption context checks fail when attempting to decrypt a file, the metadata contains
additional fields:

* ``skipped`` : ``true``
* ``reason`` : ``"Missing encryption context key or value"``
* ``missing_encryption_context_keys`` : List of required encryption context keys that were
  missing from the message.
* ``missing_encryption_context_pairs`` : List of required encryption context key-value pairs
  missing from the message.


Master Key Provider
-------------------
Information for configuring a master key provider must be provided.

Parameters may be provided using `Parameter Values`_.

These parameters are common to all master key providers:

* **provider** *(default: aws-encryption-sdk-cli::aws-kms)* : Indicator of the master key
  provider to use.

    * See `Advanced Configuration`_ for more information on using other master key providers.

* **key** *(on encrypt: at least one required, many allowed; on decrypt: one of key or discovery is required)* :
  Identifier for a wrapping key to be used in the operation. Must be an identifier understood by the specified master
  key provider. ``The discovery`` attribute is only available if you are using an ``aws-kms`` provider.

    * If using ``aws-kms`` to decrypt, `you must specify either a key or discovery with a value of true`_.
    * If using ``aws-kms`` to decrypt and specifying a key, you must use a key ARN; key ids, alias names, and alias
      ARNs are not supported.

Any additional parameters supplied are collected into lists by parameter name and
passed to the master key provider class when it is instantiated. Custom master key providers
must accept all arguments as prepared. See `Advanced Configuration`_ for more information.

Multiple master keys can be defined using multiple instances of the ``key`` argument.

Multiple master key providers can be defined using multiple ``--wrapping-keys`` groups.

If multiple master key providers are defined, the first one is treated as the primary.

If multiple master keys are defined in the primary master key provider, the first one is treated
as the primary. The primary master key is used to generate the data key.

The following logic is used to construct all master key providers. We use
``StrictAwsKmsMasterKeyProvider`` as an example.

.. code-block:: python

   # With parameters:
   --wrapping-keys provider=aws-kms key=$KEY_1 key=$KEY_2

   # KMSMasterKeyProvider is called as:
   key_provider = StrictAwsKmsMasterKeyProvider(key_ids=[$KEY_1, $KEY_2])

.. code-block:: sh

   # Single KMS CMK
   --wrapping-keys provider=aws-kms key=$KEY_ARN_1

   # Two KMS CMKs
   --wrapping-keys provider=aws-kms key=$KEY_ARN_1 key=$KEY_ARN_2

   # KMS Alias by name in default region
   --wrapping-keys provider=aws-kms key=$ALIAS_NAME

   # KMS Alias by name in two specific regions
   --wrapping-keys provider=aws-kms key=$ALIAS_NAME region=us-west-2
   --wrapping-keys provider=aws-kms key=$ALIAS_NAME region=eu-central-1

AWS KMS
```````
If you want to use the ``aws-kms`` master key provider, you can either specify that
as the provider or simply not specify a provider and allow the default value to be used.

There are some configuration options which are unique to the ``aws-kms`` master key provider:

* **profile** : Providing this configuration value will use the specified `named profile`_
  credentials.
* **discovery** *(default: false; one of key or discovery with a value of true is required)* :
  Indicates whether this provider should be in "discovery" mode. If true (enabled), the AWS Encryption CLI will attempt
  to decrypt ciphertexts encrypted with any AWS KMS CMK. If false (disabled), the AWS Encryption CLI will only attempt
  to decrypt ciphertexts encrypted with the key ARNs specified in the **key** attribute.
  Any key specified in the **key** attribute that is a KMS CMK Identier other than a key ARN will not
  be used for decryption.
* **discovery-account** *(optional; available only when discovery=true and discovery-partition is also provided)* :
  If discovery is enabled, limits decryption to AWS KMS CMKs in the specified accounts.
* **discovery-partition** *(optional; available only when discovery=true and discovery-account is also provided)* :
  If discovery is enabled, limits decryption to AWS KMS CMKs in the specified partition, e.g. "aws" or "aws-gov".
* **region** : This allows you to specify the target region.

The logic for determining which region to use is shown in the pseudocode below:

.. code-block:: python

   if key ID is an ARN:
      use region identified in ARN
   else:
      if region is specified:
         use region
      else if profile is specified and profile has a defined region:
         use region defined in profile
      else:
         use system default region

Advanced Configuration
``````````````````````
If you want to use a different master key provider, that provider must register a
`setuptools entry point`_. You can find an example of registering this entry point in the
``setup.py`` for this package.

When a provider name is specifed in a call to ``aws-encryption-cli``, the appropriate entry
point for that name is used.

Handling Multiple Entry Points
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
If multiple entry points are registered for a given name, you will need to specify the package
that registered the entry point you want to use.

In order to specify the package name, use the format: ``PACKAGE_NAME::ENTRY_POINT``.


* ``provider=aws-kms``
* ``provider=aws-encryption-sdk-cli::aws-kms``

If you supply only an entry point name and there is only one entry point registered for that
name, that entry point will be used.

If you supply only an entry point name and there is more than one entry point registered
for that name, an error will be raised showing you all of the packages that have an entry
point registered for that name.

If you supply both a package and an entry point name, that exact entry point will be used.
If it is not accessible, an error will be raised showing you all of the packages that have
an entry point registered for that name.

External Master Key Providers
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
The entry point name use must not contain the string ``::``. This is used as a namespace
separator as descibed in `Handling Multiple Entry Points`_.

When called, these entry points must return an instance of a master key provider. They must
accept the parameters prepared by the CLI as described in `Master Key Provider`_.

These entry points must be registered in the ``aws_encryption_sdk_cli.master_key_providers``
group.

If the entry point raises a ``aws_encryption_sdk_cli.exceptions.BadUserArgumentError``, the
CLI will present the raised error message to the user to indicate bad user input.

Data Key Caching
----------------
Data key caching is optional, but if used then the parameters noted as required must
be provided.  For detailed information about using data key caching with the AWS
Encryption SDK, see the `data key caching documentation`_.

Parameters may be provided using `Parameter Values`_.

Allowed parameters:

* **capacity** *(required)* : Number of entries that the cache will hold.
* **max_age** *(required)* :  Determines how long each entry can remain in the cache, beginning when it was added.
* **max_messages_encrypted** :  Determines how long each entry can remain in the cache, beginning when it was added.
* **max_bytes_encrypted** : Specifies the maximum number of bytes that a cached data key can encrypt.

Logging and Verbosity
---------------------
The ``-v`` argument allows you to tune the verbosity of the built-in logging to your desired level.
In short, the more ``-v`` arguments you supply, the more verbose the output gets.

* unset : ``aws-encryption-cli`` logs all warnings, all dependencies only log critical messages
* ``-v`` :  ``aws-encryption-cli`` performs moderate logging, all dependencies only log critical messages
* ``-vv`` :  ``aws-encryption-cli`` performs detailed logging, all dependencies only log critical messages
* ``-vvv`` :  ``aws-encryption-cli`` performs detailed logging, all dependencies perform moderate logging
* ``-vvvv`` :  ``aws-encryption-cli`` performs detailed logging, all dependencies perform detailed logging

.. table::

   +-----------------------------------------------+
   |           python logging levels               |
   +===========+====================+==============+
   | verbosity | aws-encryption-cli | dependencies |
   | flag      |                    |              |
   +-----------+--------------------+--------------+
   | unset     | WARNING            | CRITICAL     |
   +-----------+--------------------+--------------+
   | -v        | INFO               | CRITICAL     |
   +-----------+--------------------+--------------+
   | -vv       | DEBUG              | CRITICAL     |
   +-----------+--------------------+--------------+
   | -vvv      | DEBUG              | INFO         |
   +-----------+--------------------+--------------+
   | -vvvv     | DEBUG              | DEBUG        |
   +-----------+--------------------+--------------+


Configuration Files
-------------------
As with any CLI where the configuration can get rather complex, you might want to use a configuration
file to define some or all of your desired behavior.

Configuration files are supported using Python's native `argparse file support`_, which allows
you to write configuration files exactly as you would enter arguments in the shell. Configuration
file references passed to ``aws-encryption-cli`` are identified by the ``@`` prefix and the
contents are expanded as if you had included them in line. Configuration files can have any
name you desire.

.. note::

   In PowerShell, you will need to escape the ``@`` symbol so that it is sent to ``aws-encryption-cli``
   rather than interpreted by PowerShell.

For example, if I wanted to use a common master key configuration for all of my calls, I could
create a file ``master-key.conf`` with contents detailing my master key configuration.

**master-key.conf**

.. code-block:: sh

   --master-key key=A_KEY key=ANOTHER_KEY

Then, when calling ``aws-encryption-cli``, I can specify the rest of my arguments and reference
my new configuration file, and ``aws-encryption-cli`` will use the composite configuration.

.. code-block:: sh

   aws-encryption-cli -e -i $INPUT_FILE -o $OUTPUT_FILE @master-key.conf


To extend the example, if I wanted a common caching configuration for all of my calls, I could
similarly place my caching configuration in a configuration file ``caching.conf`` in this example
and include both files in my call.

**caching.conf**

.. code-block:: sh

   --caching capacity=10 max_age=60.0 max_messages_encrypted=15

.. code-block:: sh

   aws-encryption-cli -e -i $INPUT_FILE -o $OUTPUT_FILE @master-key.conf @caching.conf

Configuration files can be referenced anywhere in ``aws-encryption-cli`` parameters.

.. code-block:: sh

   aws-encryption-cli -e -i $INPUT_DIR -o $OUTPUT_DIR @master-key.conf @caching.conf --recursive

Configuration files can have many lines, include comments using ``#``. Escape characters are
platform-specific: ``\`` on Linux and MacOS and ````` on Windows. Configuration files may
also include references to other configuration files.

**my-encrypt.config**

.. code-block:: sh

   --encrypt
   @master-key.conf # Use existing master key config
   @caching.conf
   # Always recurse, but require interactive overwrite.
   --recursive
   --interactive

.. code-block:: sh

   aws-encryption-cli @my-encrypt -i $INPUT -o $OUTPUT


Encoding
--------
By default, ``aws-encryption-cli`` will always output raw binary data and expect raw binary data
as input. However, there are some cases where you might not want this to be the case.

Sometimes this might be for convenience:

* Accepting ciphertext through stdin from a human.
* Presenting ciphertext through stdout to a human.

Sometimes it might be out of necessity:

* Saving ciphertext output to a shell variable.

   * Most shells apply a system encoding to any data stored in a variable. As a result, this
     often results in corrupted data if binary data is stored without additional encoding.

* Piping ciphertext in PowerShell.

   * Similar to the above, all data passed through a PowerShell pipe is encoded using the
     system encoding.

In order to address these scenarios, we provide two optional arguments:

* ``--decode`` : Base64-decode input before processing.
* ``--encode`` : Base64-encode output after processing.

These can be used independently or together, on any valid input or output.

Be aware, however, that if you target multiple files either through a path expansion or by
targetting a directory, the requested decoding/encoding will be applied to all files.


.. _AWS Encryption SDK: https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/introduction.html
.. _message header data: http://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/message-format.html#header-structure
.. _message header authentication data: http://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/message-format.html#header-authentication
.. _Read the Docs: http://aws-encryption-sdk-cli.readthedocs.io/en/latest/
.. _GitHub: https://github.com/aws/aws-encryption-sdk-cli/
.. _cryptography: https://cryptography.io/en/latest/
.. _cryptography installation guide: https://cryptography.io/en/latest/installation/
.. _data key caching documentation: http://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/data-key-caching.html
.. _encryption context: http://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/concepts.html#encryption-context
.. _KMSMasterKeyProvider: http://aws-encryption-sdk-python.readthedocs.io/en/latest/generated/aws_encryption_sdk.key_providers.kms.html#aws_encryption_sdk.key_providers.kms.KMSMasterKeyProvider
.. _argparse file support: https://docs.python.org/3/library/argparse.html#fromfile-prefix-chars
.. _named profile: http://docs.aws.amazon.com/cli/latest/userguide/cli-multiple-profiles.html
.. _setuptools entry point: http://setuptools.readthedocs.io/en/latest/setuptools.html#dynamic-discovery-of-services-and-plugins
.. _you must specify either a key or discovery with a value of true: https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/crypto-cli-how-to.html#crypto-cli-master-key
.. _Security issue notifications: https://github.com/aws/aws-encryption-sdk-cli/tree/master/CONTRIBUTING.md#security-issue-notifications
.. _Support Policy: ./SUPPORT_POLICY.rst
