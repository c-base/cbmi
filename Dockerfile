FROM python:3.6

VOLUME /opt/cbmi

RUN apt-get update && apt-get install -y libsasl2-dev python-dev libldap2-dev libssl-dev

ADD requirements.txt /requirements.txt
RUN pip install --upgrade -r /requirements.txt

RUN ls /opt/cbmi

EXPOSE 8000
ENTRYPOINT ["/opt/cbmi/start"]



