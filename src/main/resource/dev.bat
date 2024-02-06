@echo off
java -Dlog4j.configurationFile=log4j2.xml -jar %1 --cache 0 --resource ../src/main/resource/