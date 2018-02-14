#!/bin/bash
set -ex
LOGFILE=/home/cbmi/cbmi/cbmi.log
LOGDIR=$(dirname $LOGFILE)
NUM_WORKERS=3
# user/group to run as
USER=cbmi
GROUP=cbmi
ADDRESS=127.0.0.1:8000
DJANGO_SETTINGS=cbmi.settings
DJANGO_SETTINGS_MODULE=cbmi.settings
source /home/cbmi/cbmi/bin/activate
cd /home/cbmi/cbmi
test -d $LOGDIR || mkdir -p $LOGDIR
echo "foo"
exec bin/gunicorn -w $NUM_WORKERS --bind=$ADDRESS \
  --user=$USER --group=$GROUP --log-level=debug \
  cbmi.wsgi:application \
  --log-file=$LOGFILE 2>>$LOGFILE
