ARG SRC_PATH=r.cfcr.io/hysmagus
ARG SRC_NAME=build_os_libs
ARG SRC_TAG=develop
FROM ${SRC_PATH}/${SRC_NAME}:${SRC_TAG}
ENV SRC_IMG=${SRC_PATH}/${SRC_NAME}:${SRC_TAG}


#COPY SRC
RUN mkdir -p /DAPS/
COPY . /DAPS/

#BUILD DEPENDENCIES
RUN su && cd /DAPS/depends && make
RUN su && cd /DAPS/depends && make install

CMD /bin/bash -c "trap: TERM INT; sleep infinity & wait"