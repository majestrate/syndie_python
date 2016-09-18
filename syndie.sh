#!/usr/bin/env bash

root=$(dirname $0)
venv=$root/venv
pyvenv $venv
$venv/bin/pip install -r requirements.txt 
$venv/bin/python setup.py install 
$venv/bin/python $root/main.py $@
