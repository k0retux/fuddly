#!/bin/fish
pipenv install -e .   # to trigger the generation of _version.py file
gbp dch -S -N (fuddly -v)
#gbp dch -R -N (fuddly -v) --distribution unstable --force-distribution
