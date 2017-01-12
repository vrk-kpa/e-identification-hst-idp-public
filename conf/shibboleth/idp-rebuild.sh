#!/bin/sh
export JAVA_HOME=/usr/lib/jvm/java-8-oracle
rm -fr /usr/share/tomcat/webapps/idp
cd /opt/shibboleth-idp/bin
./build.sh -Didp.target.dir=/opt/shibboleth-idp