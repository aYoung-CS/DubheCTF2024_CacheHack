FROM ubuntu:22.04

RUN sed -i "s/http:\/\/archive.ubuntu.com/http:\/\/mirrors.tuna.tsinghua.edu.cn/g" /etc/apt/sources.list && \
    apt-get update && apt-get -y dist-upgrade && \
    apt-get install -y lib32z1

RUN useradd -m ctf

WORKDIR /home/ctf

RUN cp -R /usr/lib* /home/ctf

RUN mkdir /home/ctf/dev && \
    mknod /home/ctf/dev/null c 1 3 && \
    mknod /home/ctf/dev/zero c 1 5 && \
    mknod /home/ctf/dev/random c 1 8 && \
    mknod /home/ctf/dev/urandom c 1 9 && \
    chmod 666 /home/ctf/dev/*

RUN mkdir /home/ctf/bin && \
    cp /bin/bash /home/ctf/bin/bash && \
    cp /bin/bash /home/ctf/bin/sh && \
    cp /bin/ls /home/ctf/bin && \
    cp /bin/cat /home/ctf/bin 

COPY ./start.sh /start.sh

RUN chmod +x /start.sh

COPY ./bin/ /home/ctf/
RUN chown -R root:ctf /home/ctf && \
    chmod -R 750 /home/ctf && \
    chmod 740 /home/ctf/flag

RUN mkdir -p /home/ctf/tmp/libevent/lib && \
    mv /home/ctf/libevent-2.1.so.7 /home/ctf/tmp/libevent/lib

CMD ["/start.sh"]

EXPOSE 11211