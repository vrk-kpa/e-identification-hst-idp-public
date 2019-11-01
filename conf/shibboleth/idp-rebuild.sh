#!/bin/sh
rm -fr /usr/share/tomcat/webapps/idp
cd /opt/shibboleth-idp/bin
./build.sh -Didp.target.dir=/opt/shibboleth-idp
