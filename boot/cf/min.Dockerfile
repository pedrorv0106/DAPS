
ARG SRC_PATH=ubuntu
ARG OS_VERSION=16.04
FROM ${SRC_PATH}:${OS_VERSION}
ENV SRC_IMG=${SRC_PATH}:${OS_VERSION}

RUN apt-get update
RUN apt-get install software-properties-common -y --fix-missing
RUN add-apt-repository ppa:bitcoin/bitcoin -y
RUN apt-get update
RUN apt-get install libminiupnpc-dev libevent-dev libzmq3-dev libboost-all-dev libdb4.8++-dev libdb4.8-dev nano -y --fix-missing
RUN mkdir -p /usr/bin
COPY dapscoind /usr/bin/dapscoind
COPY dapscoin-cli /usr/bin/dapscoin-cli

RUN mkdir -p ~/.dapscoin/

EXPOSE 53575 53573 53572

CMD /bin/bash -c "trap: TERM INT; sleep infinity & wait"