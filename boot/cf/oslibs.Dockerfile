ARG SRC_PATH=ubuntu
ARG OS_VERSION=16.04
FROM ${SRC_PATH}:${OS_VERSION}
ENV SRC_IMG=${SRC_PATH}:${OS_VERSION}

#INSTALL COMMON ESSENTIAL
RUN apt-get update
RUN apt-get install autotools-dev build-essential autoconf make automake openssl wget -y --fix-missing
RUN apt-get install gnupg software-properties-common debconf dialog apt-utils gcc-5 bsdmainutils curl git -y --fix-missing

#INSTALL BC
RUN add-apt-repository ppa:bitcoin/bitcoin -y
RUN apt-get update

#INSTALL LIBS
RUN apt-get install libssl-dev libboost-dev libtool  pkg-config -y --fix-missing
RUN apt-get install libminiupnpc-dev miniupnpc libdb4.8++-dev libdb4.8-dev libqrencode-dev libevent-dev -y --fix-missing

RUN apt-get install libqt5gui5 libqt5core5a libqt5dbus5 qt5-default qttools5-dev qttools5-dev-tools libprotobuf-dev libboost-all-dev protobuf-compiler -y --fix-missing
RUN apt-get install libqrencode-dev libzmq3-dev -y --fix-missing

#USE G++5
RUN apt-get install g++-5 libcurl4-openssl-dev libjansson-dev -y --fix-missing
RUN update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-5 1

RUN apt-get install libfontconfig1 mesa-common-dev libglu1-mesa-dev -y --fix-missing

CMD /bin/bash -c "trap: TERM INT; sleep infinity & wait"