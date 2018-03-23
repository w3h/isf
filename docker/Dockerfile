FROM ubuntu:16.04
MAINTAINER kira "dark_alex916@sina.com"
RUN apt-get update
RUN apt-get install -y python-dev python-pip libncurses5-dev git net-tools inetutils-ping nmap
RUN git clone https://github.com/w3h/isf.git /root/isf
RUN chmod +x /root/isf/isf.py
RUN pip install --upgrade pip
RUN pip install gnureadline
RUN pip install pycrypto
RUN pip install butterfly
RUN echo "root:123456" | chpasswd