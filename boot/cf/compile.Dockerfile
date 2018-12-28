ARG SRC_PATH=r.cfcr.io/hysmagus
ARG SRC_NAME=build_deps
ARG SRC_TAG=develop

FROM ${SRC_PATH}/${SRC_NAME}:${SRC_TAG}

ENV SRC_IMG=${SRC_PATH}/${SRC_NAME}:${SRC_TAG}
ARG BUILD_TARGET=linux
ENV BUILD_TARGET=${BUILD_TARGET}


RUN su && cd /DAPS/ && ./autogen.sh; \     
    if [ "$BUILD_TARGET" = "windows" ]; \
      then echo "Compiling for win64"; \
        CONFIG_SITE=$PWD/depends/i686-w64-mingw32/share/config.site ./configure --prefix=/; \
        make; \
        mkdir -p /win/; \
        make install DESTDIR=/win/; \
    elif [ "$BUILD_TARGET" = "linux" ]; \
       then echo "Compiling for linux"; \
         ./configure; \
         make; \
         make install; \
    else echo "Build target not recognized."; \
      exit 127; \
    fi

CMD /bin/bash -c "trap: TERM INT; sleep infinity & wait"