@echo off
java -Dlog4j.configurationFile=log4j2.xml -Xdebug -Xrunjdwp:transport=dt_socket,server=y,suspend=y,address=8000 -jar %1 --cache 0 --resource ../src/main/resource/