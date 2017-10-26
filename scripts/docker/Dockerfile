# pull ubuntu 16.04 image
FROM ubuntu:16.04

# install necessary packages
RUN 						\
	apt-get update 			\
	&& apt-get upgrade -y 	\
	&& apt-get install -y 	\
    	build-essential 	\
		gcc 				\
		make 				\
		python-pip 			\
		python2.7 			\
		nasm 				\
		git 				\
    && apt-get autoremove 	\
    && apt-get clean

# copy scripts
COPY ./scripts/ /scripts/

# clone repo to docker image
RUN   chmod 600 /scripts/github_key_file && \
      echo "IdentityFile /scripts/github_key_file\n" >> /etc/ssh/ssh_config && \
      echo "StrictHostKeyChecking no" >> /etc/ssh/ssh_config && \
      git clone --depth 1 -b integrate_tls1_3 git@github.com:kevin-kp/node.git /node

############################################
# run only when you have to upgrade openssl
# START upgrade
#
# go to openssl folder

#WORKDIR /node/deps/openssl/config

#run makefile

#RUN \
#	make

##################
# END upgrade
###

# go to node folder
WORKDIR /node

# build and install node
RUN 				\
	./configure 	\
	&& make -j2 	\
	&& make test 	\
	&& make install \

CMD ["./rebuild.sh"]
