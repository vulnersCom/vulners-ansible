FROM alpine:3.11

RUN apk add --update --no-cache openssh openrc sudo python3
RUN rc-update add sshd
RUN rc-status
RUN touch /run/openrc/softlevel

RUN NEWUSER='test' &&\
    adduser -D "${NEWUSER}" $NEWUSER &&\
    echo "$NEWUSER ALL=(ALL) ALL" > /etc/sudoers.d/$NEWUSER && chmod 0440 /etc/sudoers.d/$NEWUSER

ADD .ssh /home/test/.ssh
RUN chown -R test /home/test/.ssh
COPY docker-entrypoint.sh /home/test/docker-entrypoint.sh
RUN echo 'PasswordAuthentication no' >> /etc/ssh/sshd_config
RUN echo 'ChallengeResponseAuthentication no' >> /etc/ssh/sshd_config
RUN sed -i s/test:!/"test:*"/g /etc/shadow

EXPOSE 22
ENTRYPOINT '/home/test/docker-entrypoint.sh'