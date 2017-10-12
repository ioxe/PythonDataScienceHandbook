FROM python:3.5.4-jessie

WORKDIR /app

ADD requirements.txt /app

ENV PATH="/usr/local/bin:${PATH}"

RUN apt-get -y update \
&& apt-get -y --assume-yes install python-pip python-dev build-essential git libpng-dev pkg-config libgeos-dev build-essential \
&& pip install -r requirements.txt

CMD ["jupyter", "notebook", "--ip=0.0.0.0", "--no-browser", "--allow-root", "--port=8888"]
