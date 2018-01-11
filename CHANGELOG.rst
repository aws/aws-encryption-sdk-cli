*********
Changelog
*********

1.1.4
=====

Bugfixes
--------
* Fixed config file handling of quotes in Windows
  `#110 <https://github.com/awslabs/aws-encryption-sdk-cli/issues/110>`_


1.1.3
=====

Bugfixes
--------
* Blacklist pytest 3.3.0
  `#125 <https://github.com/awslabs/aws-encryption-sdk-cli/issues/125>`_
  `pytest-dev/pytest#2956 <https://github.com/pytest-dev/pytest/issues/2957>`_
* Expand input and output file paths in metadata
  `#120 <https://github.com/awslabs/aws-encryption-sdk-cli/issues/120>`_
* Move metadata file writer to write in binary
  `#121 <https://github.com/awslabs/aws-encryption-sdk-cli/issues/121>`_
* Skip symlink tests when running tests in Windows
  `#128 <https://github.com/awslabs/aws-encryption-sdk-cli/issues/128>`_

Operational
-----------
* Move integration tests away from using config files to using environment variables
  `#62 <https://github.com/awslabs/aws-encryption-sdk-cli/issues/62>`_

1.1.2
=====

Bugfixes
--------
* Fixed permissions issue from installing metadata files
  `#122 <https://github.com/awslabs/aws-encryption-sdk-cli/issues/122>`_

1.1.1
=====

Bugfixes
--------
* Fixed import issue with Python 3.5.0 and 3.5.1
  `#114 <https://github.com/awslabs/aws-encryption-sdk-cli/issues/114>`_

1.1.0
=====
Public release

Known Issues
------------
* Single and double quote characters break config file parsing on Windows platforms
  `#110 <https://github.com/awslabs/aws-encryption-sdk-cli/issues/110>`_
  `#111 <https://github.com/awslabs/aws-encryption-sdk-cli/issues/111>`_
* typing imports fail on Python 3.5.0 and 3.5.1
  `#114 <https://github.com/awslabs/aws-encryption-sdk-cli/issues/114>`_
  `#115 <https://github.com/awslabs/aws-encryption-sdk-cli/issues/115>`_

Bugfixes
--------
* Handle quoting in config files
  `#35 <https://github.com/awslabs/aws-encryption-sdk-cli/issues/35>`_
* Allow empty custom suffix
  `#33 <https://github.com/awslabs/aws-encryption-sdk-cli/issues/33>`_
* Handle non-POSIX paths in config files in non-POSIX environments
  `#78 <https://github.com/awslabs/aws-encryption-sdk-cli/issues/78>`_
* Expand user (``~``) and environment variables in config files
  `#89 <https://github.com/awslabs/aws-encryption-sdk-cli/issues/89>`_
* Parameter key-value pairs will no longer accept empty key or value elements
  `#94 <https://github.com/awslabs/aws-encryption-sdk-cli/issues/94>`_

New Features
------------
* Built-in base64 encoding and decoding
  `#29 <https://github.com/awslabs/aws-encryption-sdk-cli/issues/29>`_
* Strip plaintext data keys from boto3 logs
  `#54 <https://github.com/awslabs/aws-encryption-sdk-cli/issues/54>`_
* Enforce that parent directories always exist
  `#57 <https://github.com/awslabs/aws-encryption-sdk-cli/issues/57>`_
  `#100 <https://github.com/awslabs/aws-encryption-sdk-cli/issues/100>`_
* Catch single-dash dummy argument catchers for long-form arguments
  `#5 <https://github.com/awslabs/aws-encryption-sdk-cli/issues/5>`_
* Optionally output operation metadata
  `#65 <https://github.com/awslabs/aws-encryption-sdk-cli/issues/65>`_
* Optionally encryption context enforcement on decrypt
  `#69 <https://github.com/awslabs/aws-encryption-sdk-cli/issues/69>`_

Operational
-----------
* Custom master key providers now handled through setuptools entry points
  `#30 <https://github.com/awslabs/aws-encryption-sdk-cli/issues/30>`_
* Default master key provider is now namespace-specific
  `#81 <https://github.com/awslabs/aws-encryption-sdk-cli/issues/81>`_
* PyPI-Parker configuration and tox testenv added
  `#36 <https://github.com/awslabs/aws-encryption-sdk-cli/issues/36>`_
* Custom user agent value added to generated botocore client
  `#70 <https://github.com/awslabs/aws-encryption-sdk-cli/issues/70>`_
* AWS KMS master key provider configuration will no longer accept ``key`` parameter
  `#80 <https://github.com/awslabs/aws-encryption-sdk-cli/issues/80>`_

1.0.2
=====

Bugfixes
--------
* Fixed helpstring output to show input/output as required
  `#1 <https://github.com/awslabs/aws-encryption-sdk-cli/issues/1>`_
* Fixed bug when processing encrypt request with no master key provider configuration
  `#3 <https://github.com/awslabs/aws-encryption-sdk-cli/issues/3>`_
* Fixed caching CMM construction failure
  `#9 <https://github.com/awslabs/aws-encryption-sdk-cli/issues/9>`_

New Features
------------
* Added support for filename expansion
  `#4 <https://github.com/awslabs/aws-encryption-sdk-cli/issues/4>`_
* Added ability to specify profile and region for KMSMasterKeyProvider using AWS CLI-like syntax
  `#6 <https://github.com/awslabs/aws-encryption-sdk-cli/issues/6>`_
* Reworked verbosity configuration to be more useful
  `#10 <https://github.com/awslabs/aws-encryption-sdk-cli/issues/10>`_
* Addded ability to define custom output filename suffix
  `#12 <https://github.com/awslabs/aws-encryption-sdk-cli/issues/12>`_

Operational
-----------
* Added mypy coverage
  `#13 <https://github.com/awslabs/aws-encryption-sdk-cli/issues/13>`_

1.0.1
=====
* Updated `aws-encryption-sdk`_ dependency to ``>=1.3.2`` to pull in fix for
  `#7 <https://github.com/awslabs/aws-encryption-sdk-cli/issues/7>`_

1.0.0
=====
* Initial creation

.. _aws-encryption-sdk: https://github.com/awslabs/aws-encryption-sdk-python
