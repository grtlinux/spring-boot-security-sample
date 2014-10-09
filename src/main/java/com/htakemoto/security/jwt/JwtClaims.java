package com.htakemoto.security.jwt;

import java.util.List;

import lombok.Data;

@Data
public class JwtClaims
{
    private String iss;
    private long iat;
    private long exp;
    private String aud;
    private String usr;
    private List<String> roles;
}
