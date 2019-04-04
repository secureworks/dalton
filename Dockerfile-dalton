FROM python:2.7.16
MAINTAINER David Wharton

# wireshark needed for mergecap; statically compiled
#  mergecap would be smaller but doing this for now
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get -y install wireshark-common \
    p7zip-full

# for development; not needed by the app
#RUN apt-get install -y less nano net-tools

RUN mkdir -p /opt/dalton

WORKDIR /opt/dalton

COPY requirements.txt /opt/dalton/requirements.txt
RUN pip install -r requirements.txt

COPY app /opt/dalton/app
COPY run.py /opt/dalton/run.py
COPY dalton.conf /opt/dalton/dalton.conf
COPY rulesets /opt/dalton/rulesets
COPY engine-configs /opt/dalton/engine-configs

#install flowsynth
ADD https://github.com/secureworks/flowsynth/raw/master/requirements.txt /opt/flowsynth/requirements.txt
ADD https://github.com/secureworks/flowsynth/raw/master/src/flowsynth.py /opt/flowsynth/src/flowsynth.py
RUN pip install -r /opt/flowsynth/requirements.txt
RUN chmod +x /opt/flowsynth/src/flowsynth.py

CMD python /opt/dalton/run.py -c /opt/dalton/dalton.conf
