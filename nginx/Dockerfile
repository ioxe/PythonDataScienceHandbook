FROM nginx

ADD nginx.conf /etc/nginx/nginx.conf

ADD bundle.crt /etc/ssl/certs/ssl.crt

ADD *.ioxstore.com.key /etc/ssl/certs/ssl.key

ADD alphasslintermediate.pem /etc/ssl/certs/alphasslintermediate.pem

ADD *.ioxstore.com.dhparam.pem /etc/ssl/certs/dhparam.pem

EXPOSE 80 443

