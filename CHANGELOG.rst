*********
Changelog
*********

1.0.2
=====

Bugfixes
--------
* Fixed helpstring output to show input/output as required `#1 <https://github.com/awslabs/aws-encryption-sdk-cli/issues/1>`_
* Fixed bug when processing encrypt request with no master key provider configuration `#3 <https://github.com/awslabs/aws-encryption-sdk-cli/issues/3>`_
* Fixed caching CMM construction failure `#9 <https://github.com/awslabs/aws-encryption-sdk-cli/issues/9>`_

New Features
------------
* Added support for filename expansion `#4 <https://github.com/awslabs/aws-encryption-sdk-cli/issues/4>`_
* Added ability to specify profile and region for KMSMasterKeyProvider using AWS CLI-like syntax `#6 <https://github.com/awslabs/aws-encryption-sdk-cli/issues/6>`_
* Reworked verbosity configuration to be more useful `#10 <https://github.com/awslabs/aws-encryption-sdk-cli/issues/10>`_
* Addded ability to define custom output filename suffix `#12 <https://github.com/awslabs/aws-encryption-sdk-cli/issues/12>`_

Operational
-----------
* Added mypy coverage `#13 <https://github.com/awslabs/aws-encryption-sdk-cli/issues/13>`_

1.0.1
=====
* Updated `aws-encryption-sdk`_ dependency to ``>=1.3.2`` to pull in fix for `#7 <https://github.com/awslabs/aws-encryption-sdk-cli/issues/7>`_

1.0.0
=====
* Initial creation

.. _aws-encryption-sdk: https://github.com/awslabs/aws-encryption-sdk-python
