!/bin/sh

echo open-VA building utility.

export JAVA=${JAVA_HOME}/bin/java
export CLASSPATH=/lib/ant.jar:./lib/ant-launcher.jar:${JAVA_HOME}/lib/tools.jar


${JAVA} -cp ${CLASSPATH} org.apache.tools.ant.Main $*
