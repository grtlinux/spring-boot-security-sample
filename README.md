Spring Boot Security Sample
===========================

Spring Boot with Security integration with embedded LDAP user data
Spring Security is used to protect RESTFul endpoints

Requirements
------------
* [Java Platform (JDK) 6 or up](http://www.oracle.com/technetwork/java/javase/downloads/index.html)
* [Apache Maven 3.x](http://maven.apache.org/)

Quick start
-----------
1. Import the project into Eclipse as Maven project
2. Find `Application.java` from side bar, right click on the file, select 'Run As' > 'Java Application' from menu.
3. Point your browser to [http://localhost:8080](http://localhost:8080)

Get a Token (Authentication)
----------------------------
1. Run application
2. Point your browser to [http://localhost:8080/login](http://localhost:8080/login) with POST method and put `username=admin&password=password` in Payload.
3. There are more user accounts read from `WebSecurityConfig.java` and `test-server.ldif`

Access to a protected endpoint (Authentication)
-----------------------------------------------
1. Run application
2. Point your browser to [http://localhost:8080/admin](http://localhost:8080/admin) with GET method and add a custom header `Authorization` with the token you got from the above step.
3. All endpoints can be seen from `HomeController.java`. For the details of protected endpoints, check `WebSecurityConfig.java`