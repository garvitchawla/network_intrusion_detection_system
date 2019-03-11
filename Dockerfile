FROM ubuntu:latest

# author
MAINTAINER Garvit Chawla(001859169)

#extra metadata
LABEL version="1.0"
LABEL description="Image with Dockerfile for IP TCP Fragment Reassembly."
    

RUN apt-get update
RUN apt install python-pip -y
RUN apt-get install python-nids -y
RUN pip install scapy
RUN pip install oyaml
RUN pip install pyyaml
RUN pip install pynids


RUN mkdir /data
RUN chmod -R 777 /data

WORKDIR /data
ADD third.py .

ENTRYPOINT ["python", "./third.py"]
