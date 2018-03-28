# Builds Snort 2.9.7.0 Dalton agent using Snort from Ubuntu repos
FROM ubuntu:16.04
MAINTAINER David Wharton

# tcpdump is for pcap analysis; not *required* for
#  the agent but nice to have....
RUN apt-get update -y && apt-get install -y \
    python \
    tcpdump

# for debugging agent
#RUN apt-get install less

RUN DEBIAN_FRONTEND=noninteractive apt-get install -y snort=2.9.7.0-5

# the ubuntu snort package uses /usr/lib but the default config uses /usr/local/lib
RUN ln -s /usr/lib/snort_dynamicpreprocessor /usr/local/lib/snort_dynamicpreprocessor
RUN ln -s /usr/lib/snort_dynamicengine /usr/local/lib/snort_dynamicengine
RUN ln -s /usr/lib/snort_dynamicrules /usr/local/lib/snort_dynamicrules

RUN mkdir -p /opt/dalton-agent/

WORKDIR /opt/dalton-agent

COPY dalton-agent.py /opt/dalton-agent/dalton-agent.py
COPY dalton-agent.conf /opt/dalton-agent/dalton-agent.conf

CMD python /opt/dalton-agent/dalton-agent.py -c /opt/dalton-agent/dalton-agent.conf 2>&1

