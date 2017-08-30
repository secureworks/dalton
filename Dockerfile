FROM ubuntu:16.04
MAINTAINER David Wharton

RUN apt-get update -y && apt-get install -y \
    python-dev=2.7.11-1 \
    python-pip=8.1.1-2ubuntu0.4 \
    nginx=1.10.3-0ubuntu0.16.04.2

# for development; not needed by the app
RUN apt-get install -y less nano net-tools

# wireshark needed for mergecap; statically compiled
#  mergecap would be smaller but doing this for now
RUN DEBIAN_FRONTEND=noninteractive apt-get -y install wireshark-common=2.2.6+g32dac6a-2ubuntu0.16.04

RUN mkdir -p /opt/dalton/ && \
    mkdir -p /var/log/supervisord

WORKDIR /opt/dalton

COPY requirements.txt /opt/dalton/requirements.txt
RUN pip install -r requirements.txt

COPY app /opt/dalton/app
COPY run.py /opt/dalton/run.py
COPY res /opt/dalton/res
COPY dalton.conf /opt/dalton/dalton.conf
COPY rulesets /opt/dalton/rulesets
COPY engine-configs /opt/dalton/engine-configs


RUN rm /etc/nginx/nginx.conf && ln -s /opt/dalton/res/etc/nginx/nginx.conf  /etc/nginx/nginx.conf && \
    rm -rf /etc/nginx/conf.d && ln -s /opt/dalton/res/etc/nginx/conf.d /etc/nginx/conf.d && \
    ln -s /opt/dalton/res/etc/supervisord.conf /etc/supervisord.conf 


CMD supervisord -c /etc/supervisord.conf
