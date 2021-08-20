FROM ubuntu:20.04 as builder

RUN set -ex && \
    apt-get update && \
    apt-get install -y cmake && \
    apt-get install -y curl && \
    apt-get install -y wget && \
    apt-get install -y make && \
    apt-get install -y git && \
    apt-get install -y vim && \
    apt-get install -y g++ pkg-config libboost-thread-dev libboost-serialization-dev libboost-program-options-dev \
    libssl-dev libzmq3-dev libsqlite3-dev libunbound-dev libsodium-dev libunwind8-dev liblzma-dev libreadline-dev \
    libldns-dev libexpat1-dev doxygen graphviz libsqlite3-dev libcurl4-openssl-dev && \
    apt show cmake && \
    make --version && \
    g++ --version && \
    gcc --version && \
    git --version && \
    vim --version


WORKDIR /usr/local/src


RUN set -ex \
    && wget https://www.openssl.org/source/openssl-1.1.1.tar.gz \
    && tar xf openssl-1.1.1.tar.gz \
    && cd openssl-1.1.1 && ./Configure --prefix=/usr linux-x86_64 no-shared --static \
    && make -j$(nproc) && make install_sw -j$(nproc)

RUN set -ex \
    && wget https://boostorg.jfrog.io/artifactory/main/release/1.72.0/source/boost_1_72_0.tar.bz2 \
    && tar xf boost_1_72_0.tar.bz2 \
    && cd boost_1_72_0 && ./bootstrap.sh && ./b2 --prefix=/usr --build-type=minimal link=static runtime-link=static \
        --with-atomic --with-chrono --with-date_time --with-filesystem --with-program_options \
        --with-regex --with-serialization --with-system --with-thread --with-locale \
        threading=multi threadapi=pthread cxxflags=-fPIC \
        -j$(nproc) install

RUN set -ex \
    && git clone https://github.com/jedisct1/libsodium.git -b 1.0.18-RELEASE --depth=1 \
    && cd libsodium && apt-get install -y libtool \
    && ./autogen.sh && ./configure --enable-static --disable-shared --prefix=/usr \
    && make -j$(nproc) && make check && make install

RUN set -ex \
    && wget https://sqlite.org/2020/sqlite-autoconf-3310100.tar.gz \
    && tar xf sqlite-autoconf-3310100.tar.gz \
    && cd sqlite-autoconf-3310100 \
    && ./configure --disable-shared --prefix=/usr --with-pic && make -j$(nproc) && make install 

WORKDIR /src
COPY . .

RUN set -ex && \
    apt update && \
    git submodule update --init --recursive && \
    rm -rf build/release && mkdir -p build/release && cd build/release && \
    apt-get update -y &&  apt-get install libevent-dev libncurses-dev pkg-config -y && \
    cmake -DCMAKE_BUILD_TYPE=Release ../.. && make

RUN set -ex && \
    ldd /src/build/release/bin/beldexd

FROM ubuntu:20.04

RUN set -ex && \
    apt-get update && \
    apt-get --no-install-recommends --yes install ca-certificates && \
    apt-get clean && \
    rm -rf /var/lib/apt

COPY --from=builder /src/build/release/bin /usr/local/bin/

#RUN set -ex && \
 #   apt-get update && \
  #  build/release/bin /usr/local/bin/

RUN adduser --system --group --disabled-password beldex && \
    mkdir -p /wallet /home/beldex/.beldex && \
    chown -R beldex:beldex /home/beldex/.beldex && \
    chown -R beldex:beldex /wallet

VOLUME /home/beldex/.beldex

# Generate your wallet via accessing the container and run:
# cd /wallet
# beldex-wallet-cli
VOLUME /wallet

EXPOSE 19090
EXPOSE 19091

# switch to user beldex
USER beldexENTRYPOINT ["tail", "-f", "/dev/null"]
