#!/bin/bash

set -e

virtualenv cbmi
cd cbmi
source bin/activate
git clone git@github.com:c-base/cbmi.git src
cd src
git submodule init
git submodule update
pip install -r requirements.txt

cat <<EOF

Issue the following SQL statements on your devel MySQLd
    CREATE DATABASE cbmi DEFAULT CHARACTER SET = utf8;
    GRANT ALL PRIVILEGES ON cbmi.* TO cbmi@localhost IDENTIFIED BY 'cbmi';

Don't forget to run syncdb:
    python manage.py syncdb

EOF
