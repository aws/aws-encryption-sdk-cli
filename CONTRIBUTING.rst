#####################
Guide to Contributing
#####################

Getting Started
***************

Required Prerequisites
======================

* `pyenv`_
* `tox`_
* `tox-pyenv`_

Configuring Test Environment
============================

1. Install all prerequisites.
2. Install desired pyenv runtimes (see ``tox.ini``).
3. Enter the repository root directory.
4. Use ``pyenv local`` to set up local pyenv versions for all desired runtimes.

.. _pyenv: https://github.com/pyenv/pyenv
.. _tox: https://tox.readthedocs.io/en/latest/
.. _tox-pyenv: https://github.com/samstav/tox-pyenv
