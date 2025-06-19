FROM ubuntu:latest

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    make \
    g++ \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY Makefile .
COPY *.h .
COPY *.cpp .

RUN make all

VOLUME ./

ENV LD_LIBRARY_PATH=/app

CMD ["./rgrApp"]
