# logheader

* `javac -cp wlserver/server/lib/weblogic.jar:psft/pt/8.56/webserv/peoplesoft/applications/peoplesoft/PORTAL.war/WEB-INF/classes/ OPRIDAppServerFilter.java`
* Copy `OPRIDAppServerFilter.class` to `psft/pt/8.56/webserv/peoplesoft/applications/peoplesoft/PORTAL.war/WEB-INF/classes/`
* Restart WLS

The following HTTP headers will be populated (with examples):

* X-PS-APPSERVER: //localhost_9033
* X-PS-USERID: PS@192.168.88.118/ps
