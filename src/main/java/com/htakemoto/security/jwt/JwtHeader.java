package com.htakemoto.security.jwt;

import lombok.Data;

@Data
public class JwtHeader
{
    private String alg;
    private String typ;
}
