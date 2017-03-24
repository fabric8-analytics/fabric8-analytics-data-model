#!/usr/bin/env bash
# virtualenv --python /usr/bin/python2.7 env
# source env/bin/activate
# pip install -r requirements.txt
# cp src/config.py.template src/config.py
export PYTHONPATH=/src
python /src/data_importer.py $@

