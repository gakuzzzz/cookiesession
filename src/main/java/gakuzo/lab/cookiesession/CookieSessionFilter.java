/*
 * $Id: $
 * Created on 2010/01/12
 */
package gakuzo.lab.cookiesession;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.io.Serializable;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.zip.DeflaterOutputStream;
import java.util.zip.InflaterInputStream;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import javax.servlet.http.HttpSessionActivationListener;
import javax.servlet.http.HttpSessionAttributeListener;
import javax.servlet.http.HttpSessionBindingEvent;
import javax.servlet.http.HttpSessionBindingListener;
import javax.servlet.http.HttpSessionEvent;
import javax.servlet.http.HttpSessionListener;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;


public class CookieSessionFilter implements Filter {

	private final Log log = LogFactory.getLog(CookieSessionFilter.class);
	protected static final String NO_VALUE = "-";
	protected static final String DEFAULT_HMAC_ALGORITHM = "HmacSHA1";
	protected static final String DEFAULT_CRYPTION_ALGORITHM = "AES";
	
	/** Cookieのdomain属性。省略した場合、リクエストが送られたドメイン */
	protected String domain;
	/** Cookieのsecure属性をtrueにするかどうか。省略した場合 false */
	protected boolean secure;
	/** Cookieの名前に使用する接頭語。省略した場合、ContextPath の / を _ に置換した値。 */
	protected String applicationName;
	/** CookieのPath属性に指定する値。省略した場合、ContextPath。 */
	protected String path;
	/** Cookie改竄検知に使用するHMACの秘密鍵。*/
	protected SecretKey hmacSecretKey;
	/** Cookieの値を暗号化するかどうか。省略した場合 false */
	protected boolean cryption;
	/** Cookieの値を暗号化する時に使用する秘密鍵。*/
	protected SecretKey cryptionSecretKey;
	/** Session の有効期間(分)。省略した場合 0 (ブラウザ終了まで) */
	protected int defaultMaxInactiveInterval;
	/** Session 関連の EventListenerホルダー */
	protected EventListenerCollection eventListenerCollection;
	/** このWebアプリケーションの ServletContext */
	protected ServletContext servletContext;
	
	@Override
	public void init(FilterConfig config) throws ServletException {
		servletContext = config.getServletContext();
		domain = config.getInitParameter("domain");
		secure = Boolean.parseBoolean(config.getInitParameter("secure"));
		applicationName = config.getInitParameter("applicationName");
		if (applicationName == null || applicationName.equals("")) applicationName = servletContext.getContextPath().replaceAll("/", "_");
		path = config.getInitParameter("path");
		if (path == null || path.equals("")) path = servletContext.getContextPath();
		String hmacAlgorithmName = config.getInitParameter("hmacAlgorithmName");
		if (hmacAlgorithmName == null || hmacAlgorithmName.equals("")) hmacAlgorithmName = DEFAULT_HMAC_ALGORITHM;
		final String base64EncodedHmacSecretKey = config.getInitParameter("hmacSecretKey");
		if (base64EncodedHmacSecretKey == null) throw new ServletException("Not found HMAC SecretKey");
		hmacSecretKey = createSecretKey(hmacAlgorithmName, base64EncodedHmacSecretKey);
		cryption = Boolean.parseBoolean(config.getInitParameter("cryption"));
		String cryptionAlgorithmName = config.getInitParameter("cryptionAlgorithmName");
		if (cryptionAlgorithmName == null || cryptionAlgorithmName.equals("")) cryptionAlgorithmName = DEFAULT_CRYPTION_ALGORITHM;
		final String base64EncodedCryptionSecretKey = config.getInitParameter("cryptionSecretKey");
		if (cryption) cryptionSecretKey = createSecretKey(cryptionAlgorithmName, base64EncodedCryptionSecretKey);
		try {
			defaultMaxInactiveInterval = Integer.parseInt(config.getInitParameter("defaultMaxInactiveInterval"));
		} catch (final NumberFormatException e) {
			defaultMaxInactiveInterval = 0;
		}
		eventListenerCollection = new EventListenerCollection(config.getInitParameter("listener"));
	}

	@Override
	public void destroy() {
	}

	@Override
	public void doFilter(final ServletRequest servletRequest, final ServletResponse servletResponse, final FilterChain chain) throws IOException, ServletException {
		final HttpServletRequest request = (HttpServletRequest) servletRequest;
		final Cookie inputSessionCookie = findCookie(request, getSessionCookieName());
		final Cookie inputHmacCookie = findCookie(request, getHmacCookieName());
		final CookieSession beforeSession = restoreSession(inputSessionCookie, inputHmacCookie);
		final CookieSessionRequestWrapper wrapper = new CookieSessionRequestWrapper(request, beforeSession);
		try {
			chain.doFilter(wrapper, servletResponse);
		} finally {
			final CookieSession afterSession = wrapper.getCurrentSession();
			final boolean unmodify = beforeSession != null && afterSession != null && !afterSession.isModified() && !afterSession.isNew();
			final String sessionValue = unmodify ? inputSessionCookie.getValue() : storeSession(afterSession);
			final int maxAge = sessionValue.equals(NO_VALUE) ? 0 : calculateMaxAge(afterSession.getMaxInactiveInterval());
			final String hmac = sessionValue.equals(NO_VALUE) ? NO_VALUE : encode(calculateHmac(sessionValue));
			final Cookie outputSessionCookie = createCookie(getSessionCookieName(), sessionValue, maxAge);
			final Cookie outputHmacCookie = createCookie(getHmacCookieName(), hmac, maxAge);
			final HttpServletResponse response = (HttpServletResponse) servletResponse;
			response.addCookie(outputSessionCookie);
			response.addCookie(outputHmacCookie);
		}
	}
	
	protected Cookie findCookie(final HttpServletRequest request, final String cookieName) {
		final Cookie[] cookies = request.getCookies();
		if (cookies == null) return null;
		for (final Cookie cookie : cookies) {
			if (cookie.getName().equals(cookieName)) return cookie;
		}
		return null;
	}
	
	protected CookieSession restoreSession(final Cookie sessionCookie, final Cookie hmacCookie) {
		if (sessionCookie == null || hmacCookie == null) return null;
		final String encodedData = sessionCookie.getValue();
		if (!isValidHmac(encodedData, hmacCookie.getValue())) return null;
		final byte[] inputBytes = decode(encodedData);
		try {
			final InputStream byteArrayIn = new ByteArrayInputStream(inputBytes);
			final InputStream decompressIn = wrapDecompressStream(byteArrayIn);
			final InputStream decryptIn = wrapDecryptStream(decompressIn);
			final ObjectInputStream objectIn = new ObjectInputStream(decryptIn);
			try {
				final CookieSession result = (CookieSession) objectIn.readObject();
				if (isSessionTimeout(result)) return null; // Session Timeout
				result.setServletContext(servletContext);
				result.setEventListenerCollection(eventListenerCollection);
				result.setMaxInactiveInterval(defaultMaxInactiveInterval);
				result.setLastAccessedTime(System.currentTimeMillis());
				eventListenerCollection.fireDidActivateEvent(result);
				return result;
			} finally {
				objectIn.close();
			}
		} catch (final ClassNotFoundException ignore) {
		} catch (final ClassCastException ignore) {
		} catch (final IOException ignore) {
		}
		return null;
	}
	
	protected String storeSession(final CookieSession session) {
		if (session == null) return NO_VALUE;
		eventListenerCollection.fireWillPassivateEvent(session);
		try {
			final ByteArrayOutputStream byteArrayOut = new ByteArrayOutputStream();
			final OutputStream compressOut = wrapCompressStream(byteArrayOut);
			final OutputStream encryptOut = wrapEncryptStream(compressOut);
			final ObjectOutputStream objectOut = new ObjectOutputStream(encryptOut);
			try {
				objectOut.writeObject(session);
				objectOut.flush();
			} finally {
				objectOut.close();
			}
			return encode(byteArrayOut.toByteArray());
		} catch (final IOException e) {
			log.error("Cannot serialize a session.", e);
			return NO_VALUE;
		}
	}
	
	protected boolean isSessionTimeout(final CookieSession session) {
		if (defaultMaxInactiveInterval == 0) return false;
		final long timeout = System.currentTimeMillis() - session.getLastAccessedTime();
		if (timeout < 0) return true;
		return (timeout / 60000) >= defaultMaxInactiveInterval;
	}

	protected SecretKey createSecretKey(final String algorithm, final String base64encodedKey) {
		final byte[] keyBytes = Base64.decodeBase64(base64encodedKey);
		return new SecretKeySpec(keyBytes, algorithm);
	}
	
	protected OutputStream wrapEncryptStream(final OutputStream out) {
		return cryption ? new CipherOutputStream(out, getCipher(Cipher.ENCRYPT_MODE)) : out;
	}
	
	protected InputStream wrapDecryptStream(final InputStream in) {
		return cryption ? new CipherInputStream(in, getCipher(Cipher.DECRYPT_MODE)) : in;
	}
	
	protected Cipher getCipher(final int mode) {
		try {
			final Cipher cipher = Cipher.getInstance(cryptionSecretKey.getAlgorithm());
			cipher.init(mode, cryptionSecretKey);
			return cipher;
		} catch (final NoSuchAlgorithmException e) {
			// 設定値がおかしいのでシステムエラーにする。
			throw new RuntimeException(e.getMessage(), e);
		} catch (final NoSuchPaddingException e) {
			// 設定値がおかしいのでシステムエラーにする。
			throw new RuntimeException(e.getMessage(), e);
		} catch (final InvalidKeyException e) {
			// 設定値がおかしいのでシステムエラーにする。
			throw new RuntimeException(e.getMessage(), e);
		}
	}

	protected OutputStream wrapCompressStream(final OutputStream out) {
		return new DeflaterOutputStream(out);
	}
	
	protected InputStream wrapDecompressStream(final InputStream in) {
		return new InflaterInputStream(in);
	}
	
	protected String encode(final byte[] serializedBytes) {
		return new Base64(-1, null, true).encodeToString(serializedBytes);
	}
	
	protected byte[] decode(final String sessionData) {
		return Base64.decodeBase64(sessionData);
	}
	
	protected byte[] calculateHmac(final String value) {
		try {
			final Mac mac = Mac.getInstance(hmacSecretKey.getAlgorithm());
			mac.init(hmacSecretKey);
			return mac.doFinal(value.getBytes());
		} catch (final NoSuchAlgorithmException e) {
			// 設定値がおかしいのでシステムエラーにする。
			throw new RuntimeException(e.getMessage(), e);
		} catch (final InvalidKeyException e) {
			// 設定値がおかしいのでシステムエラーにする。
			throw new RuntimeException(e.getMessage(), e);
		}
	}
	
	protected boolean isValidHmac(final String value, final String hmac) {
		final byte[] result = calculateHmac(value);
		final byte[] input = decode(hmac);
		return Arrays.equals(result, input);
	}
	
	protected String getSessionCookieName() {
		return applicationName + "_sess";
	}

	protected String getHmacCookieName() {
		return getSessionCookieName() + "_hmac";
	}

	protected Cookie createCookie(final String name, final String value, final int maxAge) {
		final Cookie result = new Cookie(name, value);
		if (domain != null) result.setDomain(domain);
		result.setPath(path);
		result.setSecure(secure);
		result.setMaxAge(maxAge);
		return result;
	}
	
	/**
	 * 指定された maxInactiveInterval から Cookie の maxAge を算出します。
	 * <p>
	 * maxInactiveInterval が負の値の場合、Session はタイムアウトせずに永続化させる必要があります。
	 * Cookie には永続化の指定が存在しないため、Integer.MAX_VALUE を指定します。
	 * </p><p>
	 * maxInactiveInterval が 0 の場合、Cookie存在期間がブラウザが停止されるまでの間を意味する -1 を指定します。
	 * この挙動はこの Filter 独自の仕様です。
	 * </p><p>
	 * maxInactiveInterval が正の値の場合、maxInactiveInterval * 60 を指定します。
	 * Integerの範囲を超えてしまう場合、Integer.MAX_VALUE を指定します。
	 * </p>
	 * @return
	 */
	protected int calculateMaxAge(final int maxInactiveInterval) {
		if (maxInactiveInterval < 0) return Integer.MAX_VALUE;
		if (maxInactiveInterval == 0) return -1;
		if (Integer.MAX_VALUE / 60 < maxInactiveInterval) return Integer.MAX_VALUE;
		return maxInactiveInterval * 60;
	}
	
	protected class CookieSessionRequestWrapper extends HttpServletRequestWrapper {

		protected CookieSession session;
		
		public CookieSessionRequestWrapper(final HttpServletRequest request, final CookieSession session) {
			super(request);
			this.session = session;
		}

		@Override
		public HttpSession getSession() {
			return getSession(true);
		}

		@Override
		public HttpSession getSession(final boolean create) {
			if (session != null && !session.isInvalidated()) return session;
			if (!create) return null;
			session = new CookieSession();
			session.setServletContext(servletContext);
			session.setEventListenerCollection(eventListenerCollection);
			session.setMaxInactiveInterval(defaultMaxInactiveInterval);
			eventListenerCollection.fireCreatedEvent(session);
			return session;
		}
		
		@Override
		public String getRequestedSessionId() {
			throw new UnsupportedOperationException();
		}
		
		@Override
		public boolean isRequestedSessionIdFromCookie() {
			throw new UnsupportedOperationException();
		}

		@Override
		public boolean isRequestedSessionIdFromUrl() {
			throw new UnsupportedOperationException();
		}

		@Override
		public boolean isRequestedSessionIdFromURL() {
			throw new UnsupportedOperationException();
		}

		@Override
		public boolean isRequestedSessionIdValid() {
			throw new UnsupportedOperationException();
		}
		
		protected CookieSession getCurrentSession() {
			return session != null && session.isInvalidated() ? null : session;
		}
	}
	
	protected static class CookieSession implements HttpSession, Serializable {

		private static final long serialVersionUID = -5369206229609413188L;
		protected long creationTime;
		protected Map<String, Object> attributes;
		protected long lastAccessedTime;
		protected transient boolean isNew;
		protected transient int maxInactiveInterval;
		protected transient boolean modified;
		protected transient boolean invalidated;
		protected transient ServletContext servletContext;
		protected transient EventListenerCollection eventListenerCollection;
		
		public CookieSession() {
			creationTime = System.currentTimeMillis();
			lastAccessedTime = creationTime;
			isNew = true;
			attributes = new HashMap<String, Object>();
		}
		
		@Override
		public Object getAttribute(final String name) {
			checkInvalidated();
			if (name == null) return null;
			return attributes.get(name);
		}

		@Override
		public Enumeration<Object> getAttributeNames() {
			checkInvalidated();
			final Iterator<String> names = attributes.keySet().iterator();
			return new Enumeration<Object>() {
				@Override
				public boolean hasMoreElements() {return names.hasNext();}
				@Override
				public Object nextElement() {return names.next();}
			};
		}

		@Override
		public long getCreationTime() {
			checkInvalidated();
			return creationTime;
		}

		@Override
		public String getId() {
			throw new UnsupportedOperationException();
		}

		@Override
		public long getLastAccessedTime() {
			checkInvalidated();
			return lastAccessedTime;
		}

		@Override
		public int getMaxInactiveInterval() {
			return maxInactiveInterval;
		}

		@Override
		public ServletContext getServletContext() {
			return servletContext;
		}

		@SuppressWarnings("deprecation") /* ServletAPI の仕様のため */
		@Override
		public javax.servlet.http.HttpSessionContext getSessionContext() {
			throw new UnsupportedOperationException();
		}

		@Override
		public Object getValue(final String name) {
			return getAttribute(name);
		}

		@Override
		public String[] getValueNames() {
			checkInvalidated();
			return attributes.keySet().toArray(new String[attributes.size()]);
		}

		@Override
		public void invalidate() {
			checkInvalidated();
			eventListenerCollection.fireDestroyedEvent(this);
			for (final Iterator<Entry<String, Object>> it = attributes.entrySet().iterator(); it.hasNext();) {
				final Entry<String, Object> attribute = it.next();
				it.remove();
				eventListenerCollection.fireValueUnboundEvent(this, attribute.getKey(), attribute.getValue());
				eventListenerCollection.fireAttributeRemovedEvent(this, attribute.getKey(), attribute.getValue());
			}
			modified = true;
			invalidated = true;
		}

		@Override
		public boolean isNew() {
			checkInvalidated();
			return isNew;
		}

		@Override
		public void putValue(final String name, Object value) {
			setAttribute(name, value);
		}

		@Override
		public void removeAttribute(final String name) {
			checkInvalidated();
			final Object unbound = attributes.remove(name);
			if (unbound == null) return;
			modified = true;
			eventListenerCollection.fireValueUnboundEvent(this, name, unbound);
			eventListenerCollection.fireAttributeRemovedEvent(this, name, unbound);
		}

		@Override
		public void removeValue(final String name) {
			removeAttribute(name);
		}

		@Override
		public void setAttribute(final String name, final Object value) {
			checkInvalidated();
			if (value == null) {
				removeAttribute(name);
				return;
			}
			if (value != attributes.get(name)) {
				// ServletAPI の JavaDoc を見る限り、setAttribute後に valueBound を実行するように書いてあるが、
				// Tomcat6.0.20 の実装が追加前に呼び出しているのでそれに合わせる。
				eventListenerCollection.fireValueBoundEvent(this, name, value);
			}
			final Object unbound = attributes.put(name, value);
			modified = true;
			if (unbound == null) {
				eventListenerCollection.fireAttributeAddedEvent(this, name, value);
			} else {
				if (unbound != value) {
					eventListenerCollection.fireValueUnboundEvent(this, name, unbound);
				}
				eventListenerCollection.fireAttributeReplacedEvent(this, name, unbound);
			}
		}

		@Override
		public void setMaxInactiveInterval(final int interval) {
			maxInactiveInterval = interval;
		}

		public boolean isInvalidated() {
			return invalidated;
		}
		
		public boolean isModified() {
			return modified;
		}

		protected void setLastAccessedTime(final long lastAccessedTime) {
			this.lastAccessedTime = lastAccessedTime;
		}

		protected void setServletContext(final ServletContext servletContext) {
			this.servletContext = servletContext;
		}

		protected void setEventListenerCollection(final EventListenerCollection eventListenerCollection) {
			this.eventListenerCollection = eventListenerCollection;
		}

		protected void checkInvalidated() {
			if (invalidated) throw new IllegalStateException("This session is invalidated.");
		}

	}

	protected static class EventListenerCollection {
		
		private final Log log = LogFactory.getLog(EventListenerCollection.class);
		
		protected final List<HttpSessionActivationListener> activationListeners = new ArrayList<HttpSessionActivationListener>();
		protected final List<HttpSessionAttributeListener> attributeListeners = new ArrayList<HttpSessionAttributeListener>();
		protected final List<HttpSessionListener> sessionListeners = new ArrayList<HttpSessionListener>();
		
		public EventListenerCollection(final String listenerClassNames) {
			if (listenerClassNames == null) return;
			final ClassLoader loader = getClass().getClassLoader();
			for (final String listenerClassName : listenerClassNames.split(",")) {
				try {
					final Class<?> listenerClass = loader.loadClass(listenerClassName.trim());
					final Object listener = listenerClass.newInstance();
					if (listener instanceof HttpSessionActivationListener) {
						activationListeners.add(HttpSessionActivationListener.class.cast(listener));
					}
					if (listener instanceof HttpSessionAttributeListener) {
						attributeListeners.add(HttpSessionAttributeListener.class.cast(listener));
					}
					if (listener instanceof HttpSessionListener) {
						sessionListeners.add(HttpSessionListener.class.cast(listener));
					}
				} catch (final ClassNotFoundException ignore) {
					log.info("Cannot load an event listener class. " + listenerClassName);
				} catch (final InstantiationException e) {
					log.info("Cannot create an instance. " + listenerClassName);
				} catch (final IllegalAccessException e) {
					log.info("Cannot create an instance. " + listenerClassName);
				}
			}
		}
		
		public void fireDidActivateEvent(final HttpSession session) {
			final HttpSessionEvent event = new HttpSessionEvent(session);
			for (final HttpSessionActivationListener listener : activationListeners) {
				try {
					listener.sessionDidActivate(event);
				} catch (final Throwable e) {
					log.error("An error occurred at HttpSessionActivationListener#sessionDidActivate", e);
				}
			}
		}
		
		public void fireWillPassivateEvent(final HttpSession session) {
			final HttpSessionEvent event = new HttpSessionEvent(session);
			for (final HttpSessionActivationListener listener : activationListeners) {
				try {
					listener.sessionWillPassivate(event);
				} catch (final Throwable e) {
					log.error("An error occurred at HttpSessionActivationListener#sessionWillPassivate", e);
				}
			}
		}
		
		public void fireAttributeAddedEvent(final HttpSession session, final String name, final Object value) {
			final HttpSessionBindingEvent event = new HttpSessionBindingEvent(session, name, value);
			for (final HttpSessionAttributeListener listener : attributeListeners) {
				try {
					listener.attributeAdded(event);
				} catch (final Throwable e) {
					log.error("An error occurred at HttpSessionAttributeListener#attributeAdded", e);
				}
			}
		}

		public void fireAttributeReplacedEvent(final HttpSession session, final String name, final Object value) {
			final HttpSessionBindingEvent event = new HttpSessionBindingEvent(session, name, value);
			for (final HttpSessionAttributeListener listener : attributeListeners) {
				try {
					listener.attributeReplaced(event);
				} catch (final Throwable e) {
					log.error("An error occurred at HttpSessionAttributeListener#attributeReplaced", e);
				}
			}
		}

		public void fireAttributeRemovedEvent(final HttpSession session, final String name, final Object value) {
			final HttpSessionBindingEvent event = new HttpSessionBindingEvent(session, name, value);
			for (final HttpSessionAttributeListener listener : attributeListeners) {
				try {
				listener.attributeRemoved(event);
				} catch (final Throwable e) {
					log.error("An error occurred at HttpSessionAttributeListener#attributeRemoved", e);
				}
			}
		}
		
		public void fireValueBoundEvent(final HttpSession session, final String name, final Object value) {
			if (!(value instanceof HttpSessionBindingListener)) return;
			final HttpSessionBindingEvent event = new HttpSessionBindingEvent(session, name, value);
			try {
				HttpSessionBindingListener.class.cast(value).valueBound(event);
			} catch (final Throwable e) {
				log.error("An error occurred at HttpSessionBindingListener#valueBound", e);
			}
		}

		public void fireValueUnboundEvent(final HttpSession session, final String name, final Object value) {
			if (!(value instanceof HttpSessionBindingListener)) return;
			final HttpSessionBindingEvent event = new HttpSessionBindingEvent(session, name, value);
			try {
				HttpSessionBindingListener.class.cast(value).valueUnbound(event);
			} catch (final Throwable e) {
				log.error("An error occurred at HttpSessionBindingListener#valueUnbound", e);
			}
		}

		public void fireCreatedEvent(final HttpSession session) {
			final HttpSessionEvent event = new HttpSessionEvent(session);
			for (final HttpSessionListener listener : sessionListeners) {
				try {
					listener.sessionCreated(event);
				} catch (final Throwable e) {
					log.error("An error occurred at HttpSessionListener#sessionCreated", e);
				}
			}
		}

		public void fireDestroyedEvent(final HttpSession session) {
			final HttpSessionEvent event = new HttpSessionEvent(session);
			for (final HttpSessionListener listener : sessionListeners) {
				try {
					listener.sessionDestroyed(event);
				} catch (final Throwable e) {
					log.error("An error occurred at HttpSessionListener#sessionDestroyed", e);
				}
			}
		}
		
	}
}
