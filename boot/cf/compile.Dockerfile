ARG SRC_PATH=r.cfcr.io/hysmagus
ARG SRC_NAME=build_deps
ARG SRC_TAG=develop

FROM ${SRC_PATH}/${SRC_NAME}:${SRC_TAG}
ENV SRC_IMG=${SRC_PATH}/${SRC_NAME}:${SRC_TAG}

ARG BUILD_TARGET=linux
ENV BUILD_TARGET=${BUILD_TARGET}

ARG DESTDIR=/daps/bin/
ENV DESTDIR=$DESTDIR


RUN cd /DAPS/ && \
#     
    if [ "$BUILD_TARGET" = "windows" ]; \
      then echo "Compiling for win64" && \
        make HOST=x86_64-w64-mingw32 && \
        mkdir -p $DESTDIR/win/ && \
        make install HOST=x86_64-w64-mingw32 DESTDIR=$DESTDIR/win/; \
#
    elif [ "$BUILD_TARGET" = "linux" ]; \
       then echo "Compiling for linux" && \
         make && \
         mkdir -p $DESTDIR/linux/ && \
         make install DESTDIR=$DESTDIR/linux/; \
#
    elif [ "$BUILD_TARGET" = "mac" ]; \
       then echo "Compiling for mac" && \
         make HOST="x86_64-apple-darwin11" && \
         mkdir -p $DESTDIR/mac/ && \
         make install HOST="x86_64-apple-darwin11" DESTDIR=$DESTDIR/mac/; \
#
    else echo "Build target not recognized."; \
      exit 127; \
#
    fi

CMD /bin/bash -c "trap: TERM INT; sleep infinity & wait"