/*
 *   This program is free software: you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, either version 3 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

/*
 * DependencyHelper.java
 * Copyright (C) 2018 University of Waikato, Hamilton, NZ
 * Copyright (C) 2006 Dr. Herong Yang, http://www.herongyang.com/
 */

package com.github.fracpete.maven;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import net.sourceforge.argparse4j.ArgumentParsers;
import net.sourceforge.argparse4j.impl.Arguments;
import net.sourceforge.argparse4j.inf.ArgumentParser;
import net.sourceforge.argparse4j.inf.ArgumentParserException;
import net.sourceforge.argparse4j.inf.Namespace;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.Serializable;
import java.net.Authenticator;
import java.net.PasswordAuthentication;
import java.net.URL;
import java.net.URLConnection;
import java.security.DigestInputStream;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

/**
 * Helper class for obtaining dependency snippets for jars that are available
 * from Maven Central.
 *
 * @author FracPete (fracpete at waikato dot ac dot nz)
 * @author Herong Yang
 */
public class DependencyHelper
  implements Serializable  {

  private static final long serialVersionUID = 3161026268021202145L;

  /** hexadecimal digits. */
  public static final char HEX_DIGIT[] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};

  /** the hash placeholder. */
  public final static String PH_HASH = "{HASH}";

  /** the rest URL template. */
  public static final String REST_URL = "http://search.maven.org/solrsearch/select?q=1:%22" + PH_HASH + "%22&rows=20&wt=json";

  /** the jars. */
  protected List<String> m_Jars;

  /** the directories. */
  protected List<String> m_Dirs;

  /** the regular expression for including files. */
  protected String m_Include;

  /** the include pattern. */
  protected Pattern m_IncludePattern;

  /** the regular expression for excluding files. */
  protected String m_Exclude;

  /** the exclude pattern. */
  protected Pattern m_ExcludePattern;

  /** the proxy to use. */
  protected String m_Proxy;

  /** the proxy port to use. */
  protected int m_ProxyPort;

  /** the proxy user, if any. */
  protected String m_ProxyUser;

  /** the proxy password, if any. */
  protected String m_ProxyPassword;

  /** the verbosity level for logging output. */
  protected int m_Verbosity;

  /**
   * Initializes the object.
   */
  public DependencyHelper() {
    initialize();
  }

  /**
   * Initializes the members.
   */
  protected void initialize() {
    m_Jars           = new ArrayList<>();
    m_Dirs           = new ArrayList<>();
    m_Include        = "";
    m_IncludePattern = null;
    m_Exclude        = "";
    m_ExcludePattern = null;
    m_Proxy          = "";
    m_ProxyPort      = 80;
    m_ProxyUser      = "";
    m_ProxyPassword  = "";
    m_Verbosity      = 0;
  }

  /**
   * The jar to add.
   *
   * @param value	the full path name
   * @return		the helper itself
   */
  public DependencyHelper addJar(String value) {
    m_Jars.add(value);
    return this;
  }

  /**
   * The jars to add.
   *
   * @param value	the list of jars with full path name
   * @return		the helper itself
   */
  public DependencyHelper addJars(List<String> value) {
    m_Jars.addAll(value);
    return this;
  }

  /**
   * Returns the current list of jars.
   *
   * @return		the list of jars with full path name
   */
  public List<String> getJars() {
    return m_Jars;
  }

  /**
   * The dir to add.
   *
   * @param value	the full path name
   * @return		the helper itself
   */
  public DependencyHelper addDir(String value) {
    m_Dirs.add(value);
    return this;
  }

  /**
   * The dirs to add.
   *
   * @param value	the list of dirs with full path name
   * @return		the helper itself
   */
  public DependencyHelper addDirs(List<String> value) {
    m_Dirs.addAll(value);
    return this;
  }

  /**
   * Sets the regular expression for including jars from dirs.
   * 
   * @param value	the expression, ignored if empty string 
   */
  public void setInclude(String value) {
    m_Include = value;
    m_IncludePattern = null;
  }

  /**
   * Returns the regular expression for including jars from dirs.
   * 
   * @return		the expression, ignored if empty
   */
  public String getInclude() {
    return m_Include;
  }

  /**
   * Sets the regular expression for excluding jars from dirs.
   * 
   * @param value	the expression, ignored if empty string 
   */
  public void setExclude(String value) {
    m_Exclude = value;
    m_ExcludePattern = null;
  }

  /**
   * Returns the regular expression for excluding jars from dirs.
   * 
   * @return		the expression, ignored if empty
   */
  public String getExclude() {
    return m_Exclude;
  }
  
  /**
   * Sets the proxy to use.
   *
   * @param value	the proxy, empty string for no proxy
   */
  public void setProxy(String value) {
    m_Proxy = value;
  }

  /**
   * Returns the currently set proxy.
   *
   * @return		the proxy, empty string if not used
   */
  public String getProxy() {
    return m_Proxy;
  }

  /**
   * Sets the proxy port to use.
   *
   * @param value	the port
   */
  public void setProxyPort(int value) {
    if ((value > 0) && (value < 65536))
      m_ProxyPort = value;
    else
      System.err.println("Invalid port number: " + value);
  }

  /**
   * Returns the currently set proxy port.
   *
   * @return		the port
   */
  public int getProxyPort() {
    return m_ProxyPort;
  }

  /**
   * Sets the proxy user to use.
   *
   * @param value	the user, empty string for no proxy
   */
  public void setProxyUser(String value) {
    m_ProxyUser = value;
  }

  /**
   * Returns the currently set proxy user.
   *
   * @return		the user, empty string if not used
   */
  public String getProxyUser() {
    return m_ProxyUser;
  }

  /**
   * Sets the proxy password to use.
   *
   * @param value	the password, empty string if not required
   */
  public void setProxyPassword(String value) {
    m_ProxyPassword = value;
  }

  /**
   * Returns the currently set proxy password.
   *
   * @return		the password, empty string if not required
   */
  public String getProxyPassword() {
    return m_ProxyPassword;
  }

  /**
   * Sets the verbosity levl.
   *
   * @param value	the level, 0=off, the higher the more output
   */
  public void setVerbosity(int value) {
    if (value >= 0)
      m_Verbosity = value;
    else
      System.err.println("Invalid verbosity (>=0): " + value);
  }

  /**
   * Returns the currently verbosity level.
   *
   * @return		the level, 0=off, the higher the more output
   */
  public int getVerbosity() {
    return m_Verbosity;
  }

  /**
   * Logs the message if the verbosity level is sufficient.
   *
   * @param msg		the message to log
   * @param level	the verbosty level this message requires
   */
  protected void log(String operation, String msg, int level) {
    if (level <= m_Verbosity)
      System.err.println("[" + operation + "] " + msg);
  }

  /**
   * Returns the current list of dirs.
   *
   * @return		the list of dirs with full path name
   */
  public List<String> getDirs() {
    return m_Dirs;
  }

  /**
   * Checks the setup.
   *
   * @return		null if passed, otherwise error message
   */
  public String check() {
    if ((m_Jars.size() == 0) && (m_Dirs.size() == 0))
      return "Neither jars nor directories provided!";

    m_IncludePattern = null;
    if (!m_Include.isEmpty()) {
      try {
	m_IncludePattern = Pattern.compile(m_Include);
      }
      catch (Exception e) {
        return "Invalid include pattern '" + m_Include + "': " + e;
      }
    }

    m_ExcludePattern = null;
    if (!m_Exclude.isEmpty()) {
      try {
	m_ExcludePattern = Pattern.compile(m_Exclude);
      }
      catch (Exception e) {
        return "Invalid exclude pattern '" + m_Exclude + "': " + e;
      }
    }

    return null;
  }

  /**
   * Configures the proxy, if necessary.
   */
  protected void configureProxy() {
    if (m_Proxy.trim().isEmpty())
      return;

    if (!m_ProxyUser.trim().isEmpty()) {
      log("proxy", "setting authentication: " + m_ProxyUser + "/" + m_ProxyPassword.replaceAll(".", "*"), 2);
      Authenticator.setDefault(
	new Authenticator() {
	  @Override
	  protected PasswordAuthentication getPasswordAuthentication() {
	    return new PasswordAuthentication(m_ProxyUser, m_ProxyPassword.toCharArray());
	  }
	});
    }

    log("proxy", "setting proxy: " + m_Proxy + ":" + m_ProxyPort, 2);
    System.setProperty("http.proxyHost", m_Proxy);
    System.setProperty("http.proxyPort", "" + m_ProxyPort);
  }

  /**
   * Returns the full list of jars.
   *
   * @param errors	for collecting errors
   * @return		the complete list of jars
   */
  protected List<String> locateJars(List<String> errors) {
    List<String>	result;
    File 		dir;
    File[]		files;
    boolean		add;

    result = new ArrayList<>();

    // explicit jars
    log("locating jars", "explicit jars: " + m_Jars, 3);
    result.addAll(m_Jars);

    // traverse directories
    for (String d : m_Dirs) {
      log("locating jars", "iterating dir: " + d, 3);
      dir = new File(d);
      if (!dir.isDirectory()) {
        errors.add("Not a directory: " + d);
	continue;
      }

      files = dir.listFiles();
      if (files == null) {
        errors.add("Failed to list directories in: " + d);
        continue;
      }

      log("locating jars", "# files: " + files.length, 3);
      for (File f: files) {
        if (f.getName().equals(".") || f.getName().equals(".."))
          continue;

        // include
        if (m_IncludePattern == null)
          add = f.getName().toLowerCase().endsWith(".jar");
	else
          add = m_IncludePattern.matcher(f.getName()).matches();

	// exclude
	if (add && (m_ExcludePattern != null))
	  add = !m_ExcludePattern.matcher(f.getName()).matches();

	log("locating jars", "add file '" + f + "'? " + add, 3);
	if (add)
	  result.add(f.getAbsolutePath());
      }
    }

    log("locating jars", "all jars: " + result, 3);

    return result;
  }

  /**
   * Closes the stream, if possible, suppressing any exception.
   *
   * @param is		the stream to close
   */
  protected void closeQuietly(InputStream is) {
    if (is != null) {
      try {
	is.close();
      }
      catch (Exception e) {
	// ignored
      }
    }
  }

  /**
   * Returns a hexadecimal representation of the byte value.
   * <br><br>
   * Taken from <a href="http://www.herongyang.com/Cryptography/SHA1-Message-Digest-in-Java.html" target="_blank">here</a>.
   *
   * @param value	the value to convert
   * @return		the hexadecimal representation
   */
  public static String toHex(byte value) {
    StringBuilder	result;

    result = new StringBuilder();
    result.append(HEX_DIGIT[(value >> 4) & 0x0f]);
    result.append(HEX_DIGIT[(value) & 0x0f]);

    return result.toString();
  }

  /**
   * Computes the hash for the jar.
   *
   * @param jar		the jar to process
   * @param errors	for storing errors
   * @return		the hash, null if failed to compute
   */
  protected String computeHash(String jar, List<String> errors) {
    String		result;
    StringBuilder 	hash;
    MessageDigest	md;
    byte[]		digest;
    DigestInputStream 	stream;
    FileInputStream 	fis;
    byte[]		buffer;

    hash = new StringBuilder();
    stream = null;
    fis    = null;
    try {
      md     = MessageDigest.getInstance("SHA-1");
      fis    = new FileInputStream(jar);
      stream = new DigestInputStream(new BufferedInputStream(fis), md);
      buffer = new byte[1024];
      while (stream.read(buffer) != -1);
      digest = md.digest();
      for (byte b : digest)
	hash.append(toHex(b));
    }
    catch (Exception e) {
      errors.add("Failed to generate SHA-1 for '" + jar + "': " + e);
      return null;
    }
    finally {
      closeQuietly(stream);
      closeQuietly(fis);
    }

    result = hash.toString().toLowerCase();
    log("compute hash", result, 3);

    return result;
  }

  /**
   * Queries Maven Central.
   *
   * @param hash	the hash to use
   * @param errors	for storing errors
   * @return		the parsed JSON response, null in case of failure
   */
  protected JsonElement query(String hash, List<String> errors) {
    String			urlStr;
    URL 			url;
    URLConnection 		conn;
    BufferedInputStream		input;
    byte[]			buffer;
    byte[]			bufferSmall;
    int				len;
    int				bufSize;
    StringBuilder		content;
    JsonParser 			jp;
    JsonElement 		result;

    // query rest api
    urlStr = REST_URL.replace(PH_HASH, hash);
    log("query", "rest url: " + urlStr, 3);

    content = new StringBuilder();
    try {
      url = new URL(urlStr);
      conn = url.openConnection();
      input  = new BufferedInputStream(conn.getInputStream());
      bufSize = 1024;
      buffer = new byte[bufSize];
      while ((len = input.read(buffer)) > 0) {
	if (len < bufSize) {
	  bufferSmall = new byte[len];
	  System.arraycopy(buffer, 0, bufferSmall, 0, len);
	  content.append(new String(bufferSmall));
	}
	else {
	  content.append(new String(buffer));
	}
      }
    }
    catch (Exception e) {
      errors.add("Failed to query Maven Central using '" + urlStr + "': " + e);
      return null;
    }

    // parse JSON
    jp     = new JsonParser();
    result = jp.parse(content.toString());
    log("query", "rest response: " + result, 3);

    return result;
  }

  /**
   * Parses the JSON response from Maven Central.
   *
   * @param json	the json response object
   * @param errors	for storing errors
   * @return		the dependency snippet, null in case of error
   */
  protected String extractDependency(JsonObject json, List<String> errors) {
    String	result;
    int 	status;
    JsonObject	response;
    JsonObject	doc;
    String	gid;
    String	aid;
    String 	ver;
    String	type;

    result = null;

    if (json.has("responseHeader") && json.has("response")) {
      status = json.get("responseHeader").getAsJsonObject().get("status").getAsInt();
      if (status == 0) {
        response = json.get("response").getAsJsonObject();
        if (response.get("numFound").getAsInt() == 1) {
	  doc  = response.get("docs").getAsJsonArray().get(0).getAsJsonObject();
	  gid  = doc.get("g").getAsString();
	  aid  = doc.get("a").getAsString();
	  ver  = doc.get("v").getAsString();
	  type = doc.get("p").getAsString();
	  log("extract dep", "gid=" + gid + ", aid=" + aid + ", ver=" + ver + ", type=" + type, 3);
	  result = "<dependency>\n"
	    + "  <groupId>" + gid + "</groupId>\n"
	    + "  <artifactId>" + aid + "</artifactId>\n"
	    + "  <version>" + ver + "</version>\n";
	  if (!type.equals("jar"))
	    result += "  <type>" + type + "</type>\n";
	  result += "</dependency>";
	}
	else {
          errors.add("Found # artifacts: " + response.get("numFound").getAsInt());
	}
      }
      else {
        errors.add("Status code: " + status);
      }
    }

    return result;
  }

  /**
   * Determines the dependency for the given jar.
   *
   * @param jar		the jar to process
   * @param errors	for storing errors
   * @return		the dependency snippet, null if failed to determine
   */
  protected String determineDependency(String jar, List<String> errors) {
    String	hash;
    JsonElement	json;

    hash = computeHash(jar, errors);
    if (hash == null)
      return null;

    json = query(hash, errors);
    if (json == null)
      return null;

    return extractDependency(json.getAsJsonObject(), errors);
  }

  /**
   * Generates the dependency snippets.
   *
   * @param errors	for collecting errors
   * @return		the generated snippets
   */
  public List<String> execute(List<String> errors) {
    List<String>	result;
    List<String>	jars;
    String		dep;

    configureProxy();

    result = new ArrayList<>();
    jars   = locateJars(errors);

    for (String jar: jars) {
      dep = determineDependency(jar, errors);
      if (dep != null)
        result.add(dep);
    }

    return result;
  }
  
  /**
   * Executes the application.
   *
   * @param args	the command-line options
   * @throws Exception	if parsing fails
   */
  public static void main(String[] args) throws Exception {
    ArgumentParser 	parser;
    Namespace 		ns;

    parser = ArgumentParsers.newArgumentParser(DependencyHelper.class.getName());
    parser.description("Tools for outputting Maven dependency snippets generated from arbitrary jars.\n"
      + "For this to work, the jars must be available from Maven Central.\n"
      + "The include/exclude order is: apply include and apply exclude.\n"
      + "If no include pattern is provided all files that end in '.jar' will get added.");
    parser.addArgument("--jar")
      .setDefault(new ArrayList<String>())
      .dest("jar")
      .required(false)
      .action(Arguments.append())
      .help("The jar(s) to process.\nEither this option or '--dir' has to be provided.\nCan be supplied multiple times.");
    parser.addArgument("--dir")
      .setDefault(new ArrayList<String>())
      .dest("dir")
      .required(false)
      .action(Arguments.append())
      .help("The directory/ies containing the jars to process.\nEither this option or '--jar' has to be provided.\nCan be supplied multiple times.");
    parser.addArgument("--include")
      .setDefault("")
      .dest("include")
      .required(false)
      .action(Arguments.store())
      .help("The regular expression to use for including jars when traversing directories.");
    parser.addArgument("--exclude")
      .setDefault("")
      .dest("exclude")
      .required(false)
      .action(Arguments.store())
      .help("The regular expression to use for excluding jars when traversing directories.");
    parser.addArgument("--proxy")
      .setDefault("")
      .dest("proxy")
      .required(false)
      .action(Arguments.store())
      .help("The proxy to use.");
    parser.addArgument("--proxy-port")
      .setDefault(80)
      .dest("proxyport")
      .required(false)
      .type(Integer.class)
      .action(Arguments.store())
      .help("The proxy port to use.");
    parser.addArgument("--proxy-user")
      .setDefault("")
      .dest("proxyuser")
      .required(false)
      .action(Arguments.store())
      .help("The user for the proxy.");
    parser.addArgument("--proxy-pw")
      .setDefault("")
      .dest("proxypw")
      .required(false)
      .action(Arguments.store())
      .help("The password for the proxy.");
    parser.addArgument("--verbosity")
      .setDefault(0)
      .dest("verbosity")
      .required(false)
      .type(Integer.class)
      .action(Arguments.store())
      .help("The verbosity level for logging output.");

    ns = null;
    try {
      ns = parser.parseArgs(args);
    }
    catch (ArgumentParserException e) {
      parser.handleError(e);
    }
    catch (Throwable t) {
      throw t;
    }

    if (ns != null) {
      DependencyHelper helper = new DependencyHelper();
      helper.addJars(ns.getList("jar"));
      helper.addDirs(ns.getList("dir"));
      helper.setInclude(ns.getString("include"));
      helper.setExclude(ns.getString("exclude"));
      helper.setProxy(ns.getString("proxy"));
      helper.setProxyPort(ns.getInt("proxyport"));
      helper.setProxyUser(ns.getString("proxyuser"));
      helper.setProxyPassword(ns.getString("proxypw"));
      helper.setVerbosity(ns.getInt("verbosity"));
      String msg = helper.check();
      if (msg != null) {
        System.err.println(msg);
        parser.printHelp();
        return;
      }
      List<String> errors = new ArrayList<>();
      List<String> snippets = helper.execute(errors);
      for (String error: errors)
        System.err.println(error);
      for (String snippet: snippets)
        System.out.println(snippet);
    }
  }

}
