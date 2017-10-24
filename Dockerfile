# pull ubuntu 16.04 image
FROM ubuntu:16.04

# install necessary packages
RUN \
	apt-get update \
	&& apt-get upgrade -y \
	&& apt-get install -y \
    	build-essential \
		gcc \
		make \
		python-pip \
		python2.7 \
		nasm \
		git \
		libssl-dev \
    && apt-get autoremove \
    && apt-get clean

# copy scripts
COPY ./ /node

############################################
# run only when you have to upgrade openssl
# START upgrade
#
# go to openssl folder

#WORKDIR /node/deps/openssl/config

#run makefile

#RUN \
#	make \
#	&& make Makefile_VC-WIN32 \
#	&& make Makefile_VC-WIN64A

##################
# END upgrade
###

# go to node folder
WORKDIR /node

# build and install node
RUN \
	./configure \
	&& make -j2 \
	&& make install \
	&& make test

#CMD ["./rebuild.sh"]