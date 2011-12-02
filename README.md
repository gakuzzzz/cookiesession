# Cookie session store for JavaEE Applications

This is a servlet filter that emulate the cookie session store of Ruby on Rails.

# Features

- **Scalable**
    - The application server can be distributable without using the session replication or the load balancing with stickey cookies.

- **Thread Safe**
    - Since any access to the session is limited to a single thread, It is unnecessary to consider thread safety.

- **Security**
    - Since the cookie value is encrypted, the session can contains a sensitive data.

# Restrictions

- You cannot use methods about Session ID.
    - Because Session ID does not exist.
    - All these methods throw an `UnsupportedOperationException`.

- `HttpSessionListener#sessionDestroyed` is not necessarily called.
    - Since any session is not saved at a server, the application can not destroy a session which is timed-out.
    - If some problem occurs because of it, control by using `HttpSessionActivationListener#sessionDidActivate` etc. 
    - When `HttpSession#invalidate` is called explicitly, `HttpSessionListener#sessionDestroyed` is certainly called. 

- All objects saved at a session need to be serializable.
    - When you save unserializable objects at a session, you should make it serializable by using `HttpSessionActivationListener` etc.
    - But this is the same as using session replication. 

# How to use

Add a `filter` and a `filter-mapping` element into your `web.xml`

### Minimum

```xml
<filter>
  <filter-name>CookieSessionFilter</filter-name>
  <filter-class>gakuzo.lab.cookiesession.CookieSessionFilter</filter-class>
  <init-param>
    <description>
      A secret key used for calculation of an HMAC. This value is required.
      When you work more than one application, 
      be sure to make this secret key unique for every application.
      Otherwise, when the application name of the cookie is rewritten by the evil client, 
      the application might accept the invalid cookie.
    </description>
    <param-name>hmacSecretKey</param-name>
    <param-value>YOUR SECRET KEY STRING ENCODED BASE64</param-value>
  </init-param>
</filter>

<filter-mapping>
  <filter-name>CookieSessionFilter</filter-name>
  <url-pattern>*</url-pattern>
</filter-mapping>
```

### Maximum

```xml
<filter>
  <filter-name>CookieSessionFilter</filter-name>
  <filter-class>gakuzo.lab.cookiesession.CookieSessionFilter</filter-class>
  <init-param>
    <description>
      A secret key used for calculation of an HMAC. This value is required.
      When you work more than one application, 
      be sure to make this secret key unique for every application.
      Otherwise, when the application name of the cookie is rewritten by the evil client, 
      the application might accept the invalid cookie.
    </description>
    <param-name>hmacSecretKey</param-name>
    <param-value>YOUR SECRET KEY STRING ENCODED BASE64</param-value>
  </init-param>
  <init-param>
    <description>An algorithm name used for calculation of an HMAC. Default value is HmacSHA1.</description>
    <param-name>hmacAlgorithmName</param-name>
    <param-value>HmacSHA1</param-value>
  </init-param>
  <init-param>
    <description>The domain attribute of the cookie. Default value is ServletRequest#getServerName() </description>
    <param-name>domain</param-name>
    <param-value>localhost</param-value>
  </init-param>
  <init-param>
    <description>If true, the secure attribute of the cookie is added. Default value is false.</description>
    <param-name>secure</param-name>
    <param-value>true</param-value>
  </init-param>
  <init-param>
    <description>An application identifier of the cookie. Default value is the context path in which "/" is replaced with "_"</description>
    <param-name>applicationName</param-name>
    <param-value>example</param-value>
  </init-param>
  <init-param>
    <description>The path attribute of the cookie. Default value is the context path.</description>
    <param-name>path</param-name>
    <param-value></param-value>
  </init-param>
  <init-param>
    <description>If true, the value of the cookie is encrypted. Default value is false.</description>
    <param-name>cryption</param-name>
    <param-value>true</param-value>
  </init-param>
  <init-param>
    <description>An algorithm name used when enciphering the value of the cookie. Default value is AES.</description>
    <param-name>cryptionAlgorithmName</param-name>
    <param-value>AES</param-value>
  </init-param>
  <init-param>
    <description>
      A secret key used when enciphering the value of the cookie. 
      If the cryption parameter is true, this value is required.
    </description>
    <param-name>cryptionSecretKey</param-name>
    <param-value>YOUR SECRET KEY STRING ENCODED BASE64</param-value>
  </init-param>
  <init-param>
    <description>
      Initial maxInactiveInterval of a session. Default value is 0 (until a browser termination).
      Because of the difference of the specifications between the maxInactiveInterval of HttpSession and the maxAge of Cookie,
      this filter evaluate maxInactiveInterval as follows.
        When maxInactiveInterval is a negative value, It is necessary to make the session to be permanent.
        But since maxAge cannot have a permanent value, This filter assigns Integer.MAX_VALUE to maxAge.
        When maxInactiveInterval is 0, 
        this filter assignes -1 (which means that the cookie lives until the browser is terminated) to maxAge.
        When maxInactiveInterval is a positive value, this filter assigns maxInactiveInterval * 60,
        even though it assigns Integer.MAX_VALUE in the case of exceeding Integer.MAX_VALUE.
    </description>
    <param-name>defaultMaxInactiveInterval</param-name>
    <param-value>0</param-value>
  </init-param>
  <init-param>
    <description>
      A list of event listeners about HttpSession.
      In the Servlet API specification, 
      the servlet filter cannot get event listeners from the servlet container.
      So you must configure 
        HttpSessionActivationListener, 
        HttpSessionAttributeListener
        and HttpSessionListener 
      at this parameter instead of the listener element in web.xml.
      Describe FQCN by a comma separated list.
    </description>
    <param-name>listener</param-name>
    <param-value>
      com.example.FooHttpSessionActivationListener, 
      com.example.BarHttpSessionListener
    </param-value>
  </init-param>
</filter>

<filter-mapping>
  <filter-name>CookieSessionFilter</filter-name>
  <url-pattern>*</url-pattern>
</filter-mapping>
```

# Experiment

1.  Use Maven to launch the sample web application.

    ```
    $ mvn jetty:run
    ```

1.  Now open next URL in a browser.

    ```
    http://localhost:8080/cookiesession/index.jsp
    ```

1.  When you reload, the numerical value in this page increases.
1.  You can see the cookie value in a browser.
1.  After delete the cookie and reload, the numerical value is 0.

# License

This library is released under the Apache Software License, version 2, which should be included with the source in a file named `LICENSE`.
