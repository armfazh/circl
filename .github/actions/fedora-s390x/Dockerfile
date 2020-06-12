FROM --platform=linux/s390x multiarch/fedora:29-s390x

COPY entry.sh /entry.sh

RUN sh -c 'curl https://dl.google.com/go/go1.14.4.linux-s390x.tar.gz | tar xz -C /usr/local'
RUN ln -s /usr/local/go/bin/go /usr/local/bin/go

ENTRYPOINT ["sh", "/entry.sh"]
