
# DAPS DEPS IMG
FROM ubuntu:18.04

RUN apt-get update
RUN apt-get install gnupg software-properties-common debconf dialog apt-utils gcc bsdmainutils curl git -y --fix-missing
RUN add-apt-repository ppa:bitcoin/bitcoin -y
RUN apt-get update

RUN apt-get install autotools-dev build-essential autoconf make automake openssl -y --fix-missing

RUN apt-get install libssl-dev libboost-dev libtool pkg-config -y --fix-missing
RUN apt-get install libminiupnpc-dev miniupnpc libdb4.8++-dev libdb4.8-dev libqrencode-dev libevent-dev -y --fix-missing

RUN apt-get install libqt5gui5 libqt5core5a libqt5dbus5 qttools5-dev qttools5-dev-tools libprotobuf-dev libboost-all-dev protobuf-compiler -y --fix-missing
RUN apt-get install libqrencode-dev libzmq3-dev -y --fix-missing

RUN apt-get install g++ -y --fix-missing
#compile for windows
#RUN apt-get install g++-mingw-w64-x86-64 -y --fix-missing
#RUN update-alternatives --config x86_64-w64-mingw32-g++

RUN mkdir /DAPS/
COPY . /DAPS/

RUN make -C /DAPS/depends

RUN bash /DAPS/autogen.sh
RUN bash /DAPS/configure

RUN ls -a