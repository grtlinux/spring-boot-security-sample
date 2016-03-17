package com.htakemoto.security;

import com.htakemoto.security.jwt.JwtClaims;
import com.htakemoto.security.jwt.JwtUtil;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang.StringUtils;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.*;

import static com.htakemoto.security.Roles.USER;

@Slf4j
public class AuthUtil {

    private static final String HEADER_NAME = "Authorization";

    public static String createAuthToken(String username, Collection<SimpleGrantedAuthority> authorities) {
        Set<String> roles = new HashSet<String>();

        // set a default role
        roles.add(USER);

        // set special roles
        for (SimpleGrantedAuthority authority : authorities) {
            String role = authority.getAuthority().replaceAll("^ROLE_", "");
            roles.add(role);
        }
        return generateAuthToken(username, new ArrayList<String>(roles));
    }

    private static String generateAuthToken(String username, List<String> roles) {

        // set custom value(s) into jwt
        JwtClaims jwtClaims = new JwtClaims();
        jwtClaims.setUsr(username);
        jwtClaims.setRoles(roles);

        // Encode JWT
        String jwt = "";

        try {
            jwt = JwtUtil.generateJWT(jwtClaims);
        } catch (Exception e) {
            log.error("Invalid signature! " + e);
        }
        return jwt;
    }

    public static String getAuthToken(HttpServletRequest request) {
        try {
            String token = request.getHeader(HEADER_NAME);
            return StringUtils.isNotBlank(token) ? token : null;
        } catch (NullPointerException e) {
            return null;
        }
    }

    // used to extend expiry time
    public static String refreshAuthToken(JwtClaims jwtClaims) {
        return generateAuthToken(jwtClaims.getUsr(), jwtClaims.getRoles());
    }

    public static void addTokenInHeader(HttpServletResponse response, String token) {
        response.setHeader(HEADER_NAME, token);
    }

    public static JwtClaims decodeAuthToken(String jwt) {
        JwtClaims jwtClaims = new JwtClaims();
        if (jwt == null) {
            return null;
        }
        else {
            // Decode JWT
            try {
                // Decode with verification of Token
                Map<String,Object> decodedPayload = JwtUtil.verify(jwt);
                // Check expiry date
                if (decodedPayload.get("exp") != null &&
                        ((Integer)decodedPayload.get("exp") >= (System.currentTimeMillis() / 1000L))) {

                    // Get fields from decoded payload
                    jwtClaims.setUsr((String) decodedPayload.get("usr"));

                    // Get roles field from decoded payload
                    if (decodedPayload.get("roles") instanceof List<?>) {
                        List<String> roles = new ArrayList<String>();
                        List<?> decodedRoles = (List<?>)decodedPayload.get("roles");
                        for (Object role : decodedRoles) {
                            if (role instanceof String) {
                                roles.add((String) role);
                            }
                        }
                        jwtClaims.setRoles(roles);
                    }
                }
                else {
                    log.debug("Token is expired!");
                    return null;
                }
            } catch (Exception e) {
                log.debug("Invalid token! " + e.getMessage());
                return null;
            }
        }
        return jwtClaims;
    }
}
