# maven-dependency-helper
Helper class for automatically generating Maven dependency tag snippets by
querying Maven Central using the SHA-1 of the jar(s).

## Command-line

```
usage: com.github.fracpete.maven.DependencyHelper
       [-h] [--jar JAR] [--dir DIR] [--include INCLUDE]
       [--exclude EXCLUDE] [--proxy PROXY] [--proxy-port PROXYPORT]
       [--proxy-user PROXYUSER] [--proxy-pw PROXYPW]
       [--verbosity VERBOSITY]

Tools for outputting  Maven  dependency  snippets  generated from arbitrary
jars.
For this to work, the jars must be available from Maven Central.
The include/exclude order is: apply include and apply exclude.
If no include pattern is provided  all  files  that  end in '.jar' will get
added.

optional arguments:
  -h, --help             show this help message and exit
  --jar JAR              The jar(s) to process.
                         Either this option or '--dir' has to be provided.
                         Can be supplied multiple times.
  --dir DIR              The directory/ies containing the jars to process.
                         Either this option or '--jar' has to be provided.
                         Can be supplied multiple times.
  --include INCLUDE      The regular expression to  use  for including jars
                         when traversing directories.
  --exclude EXCLUDE      The regular expression to  use  for excluding jars
                         when traversing directories.
  --proxy PROXY          The proxy to use.
  --proxy-port PROXYPORT
                         The proxy port to use.
  --proxy-user PROXYUSER
                         The user for the proxy.
  --proxy-pw PROXYPW     The password for the proxy.
  --verbosity VERBOSITY  The verbosity level for logging  output, 0 to turn
                         off logging.
```

## Examples

### Single jar

The following example queries Maven Central for a single jar.

```
java -jar maven-dependency-helper-0.0.1-spring-boot.jar \
  --jar /some/where/5.3/iscwt-5.3.jar \
```

Which results in the following output:

```xml
<dependency>
  <groupId>de.intarsys.opensource</groupId>
  <artifactId>iscwt</artifactId>
  <version>5.3</version>
</dependency>
```


### Jars in directory

For processing all jars in a directory, but skip ones that contain `-sources`
or `-javdadoc` you can use something like this:

```
java -jar maven-dependency-helper-0.0.1-spring-boot.jar \
  --dir /some/dir/ \
  --exclude ".*(-sources|-javadoc).*"
```

Which will generate output like this:

```xml
<dependency>
  <groupId>de.intarsys.opensource</groupId>
  <artifactId>iscwt</artifactId>
  <version>5.3</version>
</dependency>
<dependency>
  <groupId>de.intarsys.opensource</groupId>
  <artifactId>isfreetype</artifactId>
  <version>5.3</version>
</dependency>
...
```


## Maven

Add the following artifact to your dependencies of your `pom.xml`:

```xml
    <dependency>
      <groupId>com.github.fracpete</groupId>
      <artifactId>maven-dependency-helper</artifactId>
      <version>0.0.1</version>
    </dependency>
```

