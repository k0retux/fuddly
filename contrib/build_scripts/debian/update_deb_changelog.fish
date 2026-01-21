#!/bin/fish
#
# First this script needs to be run within a fuddly venv at fuddly root directory;
# then the command "dpkg-buildpackage -us -uc" have to be issued in a shell outside
# of the venv and in the fuddly root directory

pipenv install -e .   # to trigger the generation of _version.py file
gbp dch -S -N (python -m fuddly.cli -v)
#gbp dch -R -N (fuddly -v) --distribution unstable --force-distribution
