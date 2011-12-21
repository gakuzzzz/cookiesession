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

- `HttpSessionListener#sessionDestroyed` is not guaranteed to be called.
    - Since any session is not saved at a server, the application can not destroy a session which is timed-out.
    - If some problem occurs because of it, control by using `HttpSessionActivationListener#sessionDidActivate` etc. 
    - When `HttpSession#invalidate` is called explicitly, `HttpSessionListener#sessionDestroyed` is certainly called. 

- All objects saved at a session need to be serializable.
    - When you have to save unserializable objects at a session, you should make it serializable by using `HttpSessionActivationListener` etc.
    - But this is the same as using session replication. 

# Dependencies

- JavaSE 5.0 or grater
- ServletAPI 2.5 or grater
- Apache Commons Codec 1.4 or grater
- Apache Commons Logging 1.1 or grater

# How to use

Add a `filter` and a `filter-mapping` element into your `web.xml`

### Example

```xml
<filter>
  <filter-name>CookieSessionFilter</filter-name>
  <filter-class>gakuzo.lab.cookiesession.CookieSessionFilter</filter-class>
  <init-param>
    <param-name>hmacSecretKey</param-name>
    <param-value>YOUR SECRET KEY STRING ENCODED BASE64</param-value>
  </init-param>
</filter>

<filter-mapping>
  <filter-name>CookieSessionFilter</filter-name>
  <url-pattern>*</url-pattern>
</filter-mapping>
```

## Required parameters

<table>
  <thead>
    <tr>
      <th>param-name</th><th>description</th>
    </tr>
  </thead>
  <tbody>
    <tr>
       <td>hmacSecretKey</td>
       <td>
         A secret key used for calculation of an HMAC. This value is required.
         When you work more than one application, be sure to make this secret key unique for every application.
         Otherwise, when the application name of the cookie is rewritten by the evil client, 
         the application might accept the invalid cookie.
       </td>
    </tr>
  </tbody>
</table>


## Optional parameters

<table>
  <thead>
    <tr>
      <th>param-name</th>
      <th>default</th>
      <th>description</th>
    </tr>
  </thead>
  <tbody>
    <tr>
       <td>hmacAlgorithmName</td>
       <td>HmacSHA1</td>
       <td>An algorithm name used for calculation of an HMAC.</td>
    </tr>
    <tr>
       <td>domain</td>
       <td>ServletRequest #getServerName</td>
       <td>The domain attribute of the cookie.</td>
    </tr>
    <tr>
       <td>secure</td>
       <td>false</td>
       <td>If true, the secure attribute of the cookie is added.</td>
    </tr>
    <tr>
       <td>applicationName</td>
       <td>The context path in which "/" is replaced with "_"</td>
       <td>An application identifier of the cookie.</td>
    </tr>
    <tr>
       <td>path</td>
       <td>The context path</td>
       <td>The path attribute of the cookie.</td>
    </tr>
    <tr>
       <td>cryption</td>
       <td>false</td>
       <td>If true, the value of the cookie is encrypted.</td>
    </tr>
    <tr>
       <td>cryptionAlgorithmName</td>
       <td>AES</td>
       <td>An algorithm name used when enciphering the value of the cookie.</td>
    </tr>
    <tr>
       <td>cryptionSecretKey</td>
       <td></td>
       <td>
          A secret key used when enciphering the value of the cookie.
          If the cryption parameter is true, this value is required.
       </td>
    </tr>
    <tr>
       <td>defaultMaxInactiveInterval</td>
       <td>0</td>
       <td>
          Initial maxInactiveInterval of a session. Default value is 0 (until a browser termination).
          Because of the difference of the specifications between the maxInactiveInterval of HttpSession and the maxAge of Cookie,
          this filter evaluate maxInactiveInterval as follows.
          <ul>
            <li>
            When maxInactiveInterval is a negative value, It is necessary to make the session to be permanent.
            But since maxAge cannot have a permanent value, This filter assigns Integer.MAX_VALUE to maxAge.
            </li><li>
            When maxInactiveInterval is 0, 
            this filter assignes -1 (which means that the cookie lives until the browser is terminated) to maxAge.
            </li><li>
            When maxInactiveInterval is a positive value, this filter assigns maxInactiveInterval * 60,
            even though it assigns Integer.MAX_VALUE in the case of exceeding Integer.MAX_VALUE.
            </li>
          </ul>
       </td>
    </tr>
    <tr>
       <td>listener</td>
       <td></td>
       <td>
          A list of event listeners about HttpSession.
          In the Servlet API specification, 
          the servlet filter cannot get event listeners from the servlet container.
          So you must configure 
            HttpSessionActivationListener, 
            HttpSessionAttributeListener
            and HttpSessionListener 
          at this parameter instead of the listener element in web.xml.
          Describe FQCN by a comma separated list.
       </td>
    </tr>
  </tbody>
</table>


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
1.  After deleting the cookie and reload, the numerical value will be 0.

# License

This library is released under the Apache Software License, version 2, which should be included with the source in a file named `LICENSE`.
