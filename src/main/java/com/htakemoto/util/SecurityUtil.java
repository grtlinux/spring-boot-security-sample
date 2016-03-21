package com.htakemoto.util;

import com.auth0.jwt.Algorithm;
import com.auth0.jwt.JWTSigner;
import com.auth0.jwt.JWTVerifier;
import com.htakemoto.config.AppConfig;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.collections.map.HashedMap;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;

import javax.annotation.PostConstruct;
import java.util.*;

import static com.htakemoto.security.Roles.USER;

@Slf4j
@Component
public class SecurityUtil {

    @Autowired
    AppConfig appConfig;

    private static JWTSigner signer = null;
    private static JWTVerifier verifier = null;

    @PostConstruct
    void init() {
        byte[] base64DecodedSecretKey = Base64.decodeBase64(appConfig.getJwtPrivateKey());
        signer = new JWTSigner(base64DecodedSecretKey);
        verifier = new JWTVerifier(base64DecodedSecretKey, appConfig.getJwtAudience(), appConfig.getJwtIssuer());
    }

    public String createAuthToken(String username, Collection<SimpleGrantedAuthority> authorities) {
        Set<String> roles = new HashSet<String>();

        // set a default role
        roles.add(USER);

        // set special roles
        for (SimpleGrantedAuthority authority : authorities) {
            String role = authority.getAuthority().replaceAll("^ROLE_", "");
            roles.add(role);
        }
        return generateJWT(username, new ArrayList<String>(roles));
    }

    public String generateJWT(String username, List<String> roles) {
        try {
            Integer currentTimeInSeconds = (int)(System.currentTimeMillis() / 1000);
            Integer expiryTimeInSeconds = (int)(currentTimeInSeconds + appConfig.getJwtExpiryInMinutes() * 60);
            Map<String, Object> claims = new HashedMap();
            claims.put("iss", appConfig.getJwtIssuer());
            claims.put("aud", appConfig.getJwtAudience());
            claims.put("iat", currentTimeInSeconds);
            claims.put("exp", expiryTimeInSeconds);
            claims.put("usr", username);
            claims.put("roles", roles);
            JWTSigner.Options jwtOptions = new JWTSigner.Options();
            jwtOptions.setAlgorithm(Algorithm.HS256);
            return signer.sign(claims, jwtOptions);
        } catch (Exception e) {
            log.error("Failed to generate a token: " + e.getMessage());
            return "";
        }
    }

    public Map verifyJWT(String jwt) {
        try {
            return verifier.verify(jwt);
        } catch (Exception e) {
            log.error("Invalid signature! " + e.getMessage());
            return null;
        }
    }
}
