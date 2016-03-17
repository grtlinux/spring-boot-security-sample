package com.htakemoto.security.jwt;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.util.Map;

import javax.annotation.PostConstruct;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import com.auth0.jwt.JWTSigner;
import com.auth0.jwt.JWTVerifyException;
import org.apache.commons.codec.binary.Base64;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import com.auth0.jwt.JWTVerifier;
import com.fasterxml.jackson.core.JsonGenerationException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.htakemoto.config.AppConfig;

@Component
public class JwtUtil {

    // NOTE: The JWT must conform with the general format rules specified below
    //       http://tools.ietf.org/html/draft-jones-json-web-token-10

    private static String PRIVATE_KEY;
    private static String AUDIENCE;
    private static String ISSUER;
    private static long TOKEN_EXPIRY_TIME;

    private static ObjectMapper mapper;
    private static AppConfig appConfig;

    private static JWTSigner signer = null;
    private static JWTVerifier verifier = null;

    @PostConstruct
    private void init() {
        PRIVATE_KEY = appConfig.getJwtPrivateKey();
        AUDIENCE = appConfig.getJwtAudience();
        ISSUER = appConfig.getJwtIssuer();
        TOKEN_EXPIRY_TIME = appConfig.getJwtExpiryInMinutes();

        byte[] base64DecodedSecretKey = Base64.decodeBase64(PRIVATE_KEY);
        signer = new JWTSigner(base64DecodedSecretKey);
        verifier = new JWTVerifier(base64DecodedSecretKey, AUDIENCE, ISSUER);
    }

    @Autowired
    public void setAppConfig(AppConfig c) {
        appConfig = c;
    }
    @Autowired
    public void setMapper(ObjectMapper om) {
        mapper = om;
    }

    /**
     * JWT Generator
     * @param claims
     * @return
     * @throws JsonGenerationException
     * @throws JsonMappingException
     * @throws IOException
     * @throws InvalidKeyException
     * @throws NoSuchAlgorithmException
     */

    public static String generateJWT(JwtClaims claims) throws JsonGenerationException, JsonMappingException, IOException, InvalidKeyException, NoSuchAlgorithmException {

        StringBuffer token = new StringBuffer();

        //Encode JWT Header and add it to token
        JwtHeader header = new JwtHeader();
        header.setAlg("HS256");
        header.setTyp("JWT");
        String headerJsonString = mapper.writeValueAsString(header);
        token.append(Base64.encodeBase64URLSafeString(headerJsonString.getBytes("UTF-8")));

        //Separate with a period
        token.append(".");

        //Create JWT Claims and add it to token
        claims.setAud(AUDIENCE);
        claims.setIss(ISSUER);
        claims.setIat(System.currentTimeMillis() / 1000L);
        claims.setExp(claims.getIat() + TOKEN_EXPIRY_TIME * 60L);
        String claimsJsonString = mapper.writeValueAsString(claims);
        token.append(Base64.encodeBase64URLSafeString(claimsJsonString.getBytes("UTF-8")));

        //Create JWT Footer (signature) and add it to token
        String signed256 = generateSignature(token.toString(), true);
        token.append("." + signed256);

        return token.toString();
    }

    private static String generateSignature(String signingInput, boolean isSecretBase64Encoded) throws NoSuchAlgorithmException, InvalidKeyException {

        String algorithm = "HmacSHA256";

        Mac mac = Mac.getInstance(algorithm);

        if (isSecretBase64Encoded) {
            mac.init(new SecretKeySpec(Base64.decodeBase64(PRIVATE_KEY), algorithm));
        }
        else {
            mac.init(new SecretKeySpec(PRIVATE_KEY.getBytes(), algorithm));
        }

        return Base64.encodeBase64URLSafeString(mac.doFinal(signingInput.getBytes()));
    }

    /**
     * JWT Verifier
     * @throws IOException
     * @throws SignatureException
     * @throws IllegalStateException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     */

    public static Map<String, Object> verify(String token) throws NoSuchAlgorithmException, InvalidKeyException, IllegalStateException, IOException, SignatureException, JWTVerifyException {
        return verifier.verify(token);
    }
}
