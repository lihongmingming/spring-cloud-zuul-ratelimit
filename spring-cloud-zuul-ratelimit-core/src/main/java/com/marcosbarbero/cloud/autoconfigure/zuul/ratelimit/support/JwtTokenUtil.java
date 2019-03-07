package com.marcosbarbero.cloud.autoconfigure.zuul.ratelimit.support;

import java.io.Serializable;
import java.util.Date;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.impl.DefaultClaims;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public class JwtTokenUtil implements Serializable {
	private static final int MILLISECOND = 1000;
	private static final long serialVersionUID = -3301605591108950415L;
	private static final String CLAIM_KEY_USER = "user";
	private static final String CLAIM_KEY_USERCODE = "userCode";
	private static final String CLAIM_KEY_USERNAME = "userName";
	private static final String CLAIM_KEY_CREATED = "created";

	@Value("${jwt.secret}")
	private String secret;
	@Value("${jwt.header}")
	private String header;
	@Value("${jwt.expiration}")
	private Long expiration;
	@Value("${jwt.tokenHead}")
	private String tokenHead;

	/**
	 * 获得jwt中的内容
	 * 
	 * @param attribute
	 *            属性名
	 * @return
	 */
	public Object getAttribute(String attribute) {
		HttpServletRequest req = getHttpServletRequest();
		String authHeader = req.getHeader(header);
		final String authToken = authHeader.substring(tokenHead.length());
		final Claims claims = getClaimsFromToken(authToken);
		return claims.get(attribute);
	}
	/**
	 * 获得当前登录用户的代码
	 * 
	 * @return
	 */
	public String getUserCode() {
		HttpServletRequest req = getHttpServletRequest();
		String authHeader = req.getHeader(header);
		final String authToken = authHeader.substring(tokenHead.length());
		return this.getUserCodeFromToken(authToken);
	}

	public String getUserCodeFromToken(String token) {
		String username;
		try {
			final Claims claims = getClaimsFromToken(token);
			username = (String) claims.get(CLAIM_KEY_USERCODE);
		} catch (Exception e) {
			username = null;
			log.warn("{}", e.getMessage(), e);

		}
		return username;
	}

	public String getUsernameFromToken(String token) {
		String username;
		try {
			final Claims claims = getClaimsFromToken(token);
			username = (String) claims.get(CLAIM_KEY_USERNAME);
		} catch (Exception e) {
			username = null;
			log.warn("{}", e.getMessage(), e);
		}
		return username;
	}

	private Date getCreatedDateFromToken(String token) {
		Date created;
		try {
			final Claims claims = getClaimsFromToken(token);
			created = new Date((Long) claims.get(CLAIM_KEY_CREATED));
		} catch (Exception e) {
			created = null;
			log.warn("{}", e.getMessage(), e);
		}
		return created;
	}

	private Date getExpirationDateFromToken(String token) {
		Date expirationDate;
		try {
			final Claims claims = getClaimsFromToken(token);
			expirationDate = claims.getExpiration();
		} catch (Exception e) {
			expirationDate = null;
			log.warn("{}", e.getMessage(), e);
		}
		return expirationDate;
	}

	private Claims getClaimsFromToken(String token) {
		Claims claims;
		try {
			claims = Jwts.parser().setSigningKey(secret).parseClaimsJws(token).getBody();
		} catch (Exception e) {
			claims = new DefaultClaims();
			log.warn("{}", e.getMessage(), e);
		}
		return claims;
	}

	private Date generateExpirationDate() {
		return new Date(System.currentTimeMillis() + expiration * MILLISECOND);
	}

	private Boolean isTokenExpired(String token) {
		final Date expirationDate = getExpirationDateFromToken(token);
		if (expirationDate == null) {
			return false;
		}
		return expirationDate.before(new Date());
	}

	private static Boolean isCreatedBeforeLastPasswordReset(Date created, Date lastPasswordReset) {
		return (lastPasswordReset != null && created.before(lastPasswordReset));
	} 

	private String generateToken(Map<String, Object> claims) {
		return Jwts.builder().setClaims(claims).setExpiration(generateExpirationDate())
				.signWith(SignatureAlgorithm.HS512, secret).compact();
	}

	public Boolean canTokenBeRefreshed(String token, Date lastPasswordReset) {
		final Date created = getCreatedDateFromToken(token);
		return !isCreatedBeforeLastPasswordReset(created, lastPasswordReset) && !isTokenExpired(token);
	}

	/**
	 * 刷新token
	 * 
	 * @param token
	 * @return
	 */
	public String refreshToken(String token) {
		String refreshedToken;
		try {
			final Claims claims = getClaimsFromToken(token);
			claims.put(CLAIM_KEY_CREATED, new Date());
			refreshedToken = generateToken(claims);
		} catch (Exception e) {
			refreshedToken = null;
			log.warn("{}", e.getMessage(), e);
		}
		return refreshedToken;
	}
	/**
	 * 获得HttpServletRequest
	 * @return
	 */
	public static HttpServletRequest getHttpServletRequest() {
		return ((ServletRequestAttributes) RequestContextHolder.getRequestAttributes()).getRequest();
	}
}
