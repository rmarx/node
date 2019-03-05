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
      git clone --depth 1 -b add_quicker_support-draft-15 git@github.com:kevin-kp/node.git /node

############################################
## run only when you have to upgrade openssl (e.g., from a new version from tatsuhiro)
## START upgrade
# WORKDIR /node
# git clone --depth 1 -b quic-draft-15 https://github.com/tatsuhiro-t/openssl /node/deps/openssl/ # this overwrites the old openSSL with the new 
# WORKDIR /node/deps/openssl/config
# make # this will update files in /node/deps/openssl/config/archs/ which we need to build openssl for Node
## END upgrade
############################################

# go to node folder
WORKDIR /node

# build and install node
# asm-mode (better perf) currently doesn't seem to work, no idea yet why... 
RUN 				\
	./configure --openssl-no-asm	\
	&& make -j$(nproc) 	\
	&& make install

CMD ["./scripts/rebuild.sh"]
