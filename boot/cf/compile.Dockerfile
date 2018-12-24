ARG SRC_PATH=r.cfcr.io/hysmagus
ARG SRC_NAME=build_deps
ARG SRC_TAG=develop
FROM ${SRC_PATH}/${SRC_NAME}:${SRC_TAG}
ENV SRC_IMG=${SRC_PATH}/${SRC_NAME}:${SRC_TAG}

#AUTOGEN AND CONFIGURE DAPS
RUN su && cd /DAPS/ && bash ./autogen.sh
RUN su && cd /DAPS/ && bash ./configure

#BUILD AND INSTALL DAPS
RUN su && cd /DAPS/ && make 
RUN su && cd /DAPS/ && make install 

CMD /bin/bash