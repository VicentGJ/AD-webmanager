FROM ubuntu:22.04
WORKDIR /app

COPY . ./
RUN apt update
RUN apt -y install --no-install-recommends python3-pip python3-venv
RUN python3 -m venv venv
RUN . venv/bin/activate
RUN apt install -y --no-install-recommends build-essential python3-dev libldap2-dev libsasl2-dev tox lcov valgrind
RUN echo 'slapd/root_password password password' | debconf-set-selections && \
    echo 'slapd/root_password_again password password' | debconf-set-selections && \
    export DEBIAN_FRONTEND=noninteractive && \ 
    apt install -y slapd ldap-utils
RUN pip3 install -r requirements.txt
EXPOSE 8080
CMD ["python3","ADwebmanager.py"]
