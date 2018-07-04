@echo off

echo open-VA building utility.

set JAVA=%JAVA_HOME%\bin\java
set CLASSPATH=./lib/ant.jar;./lib/ant-launcher.jar;"%JAVA_HOME%/lib/tools.jar"


"%JAVA%" -cp %CLASSPATH% org.apache.tools.ant.Main %1
