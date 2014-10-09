package com.htakemoto.config;

import lombok.Getter;
import lombok.Setter;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Component
@ConfigurationProperties(prefix="configuration")
@Getter
@Setter
public class AppConfig {
    
    @Value("${configuration.security.jwtPrivateKey}")
    private String jwtPrivateKey;
    
    @Value("${configuration.security.jwtAudience}")
    private String jwtAudience;
    
    @Value("${configuration.security.jwtIssuer}")
    private String jwtIssuer;
    
    @Value("${configuration.security.jwtExpiryInMinutes}")
    private long jwtExpiryInMinutes;
}
