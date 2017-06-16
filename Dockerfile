# Dockerfile
#
# Build and demo Iot-Poc in a Debian-based container
#
# To build and run this container:
# docker build --no-cache -t miracl/iot-poc:demo .
# ------------------------------------------------------------------------------

FROM miracl/alldev
MAINTAINER Alessandro Budroni <alessandro.budroni@miracl.com>

ENV DEBIAN_FRONTEND noninteractive
ENV TERM linux
RUN echo 'debconf debconf/frontend select Noninteractive' | debconf-set-selections
ENV HOME /root
ENV DISPLAY :0

# Install dependencies
RUN apt-get update && \
apt-get install nodejs \
npm

# Install npm modules
RUN npm install -g jake && \
npm install jake && \
npm install fs && \
npm install colors && \
npm install handlebars && \
npm install chai && \
npm install -g mocha && \
npm install -g mocha-circleci-reporter

# Build and demo Iot-PoC
RUN mkdir -p /root/src/milagro-crypto-js
ADD ./ /root/src/milagro-crypto-js
WORKDIR /root/src/milagro-crypto-js

RUN jake build:all --t && \
jake test:choice[All]

COPY /root/src/milagro-crypto-js/target/build_All ./target/
