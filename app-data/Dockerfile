FROM alpine:latest

RUN apk add --update curl && \
    rm -rf /var/cache/apk/*

WORKDIR /seed

COPY ./notebooks notebooks

WORKDIR notebooks

RUN curl https://s3.amazonaws.com/openrecipes/20170107-061401-recipeitems.json.gz > recipeitems-latest.json.gz && gunzip recipeitems-latest.json.gz \
&& curl -o FremontBridge.csv https://data.seattle.gov/api/views/65db-xm6k/rows.csv?accessType=DOWNLOAD \
&& curl -O https://raw.githubusercontent.com/jakevdp/marathon-data/master/marathon-data.csv \
&& curl -O https://data.giss.nasa.gov/pub/gistemp/gistemp250.nc.gz && gunzip gistemp250.nc.gz