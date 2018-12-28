ARG SRC_PATH=r.cfcr.io/hysmagus
ARG SRC_NAME=build_os_libs
ARG SRC_TAG=develop

FROM ${SRC_PATH}/${SRC_NAME}:${SRC_TAG}

ENV SRC_IMG=${SRC_PATH}/${SRC_NAME}:${SRC_TAG}
ARG BUILD_TARGET=linux
ENV BUILD_TARGET=${BUILD_TARGET}


#COPY SRC
RUN mkdir -p /DAPS/
COPY . /DAPS/

#BUILD DEPENDENCIES
RUN su && cd /DAPS/depends; \
    if [ "$BUILD_TARGET" = "windows" ]; \
      then echo "Building dependencies for win64"; \
        apt-get install g++-mingw-w64-x86-64 -y --fix-missing; \
        echo "1\n" | update-alternatives --config x86_64-w64-mingw32-g++; \
        PATH=$(echo "$PATH" | sed -e 's/:\/mnt.*//g'); \
        make HOST=x86_64-w64-mingw32; \
    elif [ "$BUILD_TARGET" = "linux" ]; \
       then echo "Building dependencies for linux"; \
       make; \
    else echo "Build target not recognized."; \
      exit 127; \
    fi
    
RUN su && cd /DAPS/depends && make install

CMD /bin/bash -c "trap: TERM INT; sleep infinity & wait"