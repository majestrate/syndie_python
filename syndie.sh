#!/usr/bin/env bash

root=$(dirname $0)
venv=$root/venv
#/usr/bin/pyvenv $venv
#source $venv/bin/activate
pip3 install -r requirements.txt --user
python3 setup.py install --user
python3 $root/main.py $@
