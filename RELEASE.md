How to make a release
=====================

* Switch to Java 8 (`. java8`)
* Run the following command to deploy the artifact:

  ```
  mvn release:clean release:prepare release:perform
  ```

* Push all changes
* Create a new release on Github using the Maven-generated tag
* Add notes and upload the `*-spring-boot.jar` artifact from the `target` directory