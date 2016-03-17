package com.htakemoto.security;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.GenericFilterBean;

import com.htakemoto.security.jwt.JwtClaims;

@Component
public class AuthFilter extends GenericFilterBean {

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain filterChain) throws IOException, ServletException {

        String jwt = AuthUtil.getAuthToken((HttpServletRequest) request);
        JwtClaims jwtClaims = AuthUtil.decodeAuthToken(jwt);
        
        SecurityContext contextBeforeChainExecution = createSecurityContext(jwtClaims);
        
        try {
            SecurityContextHolder.setContext(contextBeforeChainExecution);
            if (contextBeforeChainExecution.getAuthentication() != null && contextBeforeChainExecution.getAuthentication().isAuthenticated()) {
                String newJwt = AuthUtil.refreshAuthToken(jwtClaims);
                AuthUtil.addTokenInHeader((HttpServletResponse) response, newJwt);
            }
            filterChain.doFilter(request, response);
        }
        finally {
            // Clear the context and free the thread local
            SecurityContextHolder.clearContext();
        }
    }
    
    private SecurityContext createSecurityContext(JwtClaims jwtClaims) {
        if (jwtClaims != null && jwtClaims.getUsr() != null && jwtClaims.getRoles() != null) {
            SecurityContextImpl securityContext = new SecurityContextImpl();
            Collection<GrantedAuthority> authorities = new ArrayList<GrantedAuthority>();
            for (String role: jwtClaims.getRoles()) {
                SimpleGrantedAuthority authority = new SimpleGrantedAuthority("ROLE_"+role);
                authorities.add(authority);
            }
            Authentication authentication = new UsernamePasswordAuthenticationToken(jwtClaims.getUsr(), "", authorities);
            securityContext.setAuthentication(authentication);
            return securityContext;
        }
        return SecurityContextHolder.createEmptyContext();
    }
}
