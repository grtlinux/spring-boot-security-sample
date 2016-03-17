package com.htakemoto.config;

import static com.htakemoto.security.Roles.ADMIN;
import static com.htakemoto.security.Roles.MANAGER;
import static com.htakemoto.security.Roles.USER;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.Collection;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.htakemoto.security.SimpleCORSFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutFilter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.htakemoto.security.AuthFilter;
import com.htakemoto.security.AuthUtil;
import org.springframework.security.web.header.HeaderWriterFilter;

@Configuration
@EnableWebSecurity
//@EnableGlobalMethodSecurity(prePostEnabled = true)
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {
    
    private static final String ACCESS_DENIED_JSON = "{\"message\":\"You are not privileged to request this resource.\", \"access-denied\":true,\"cause\":\"AUTHORIZATION_FAILURE\"}";
    private static final String UNAUTHORIZED_JSON = "{\"message\":\"Full authentication is required to access this resource.\", \"access-denied\":true,\"cause\":\"NOT AUTHENTICATED\"}";

    @Autowired SimpleCORSFilter simpleCORSFilter;
    @Autowired AuthFilter authFilter;
    
    @Autowired
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        
        auth
            .inMemoryAuthentication()
                .withUser("user").password("password").roles(USER)
                .and()
                .withUser("manager").password("password").roles(MANAGER)
                .and()
                .withUser("admin").password("password").roles(ADMIN);
        
        auth
            .ldapAuthentication()
                .userDnPatterns("uid={0},ou=people")
                .groupSearchFilter("member={0}")
                .groupSearchBase("ou=groups")
                .groupRoleAttribute("ou")
                .contextSource()
                    .ldif("classpath:test-server.ldif");
        
// For LDAP or Active Directory, uncomment the following code.
//        auth
//            .ldapAuthentication()
//                // Authentication
//                .userSearchFilter("(sAMAccountName={0})")
//                .userSearchBase("")
//                // Authorization
//                .groupSearchFilter("member={0}")
//                .groupSearchBase("OU=Member,OU=Authorization Groups")
//                .groupRoleAttribute("CN")
//                // LDAP Configuration
//                .contextSource()
//                    .url("ldap://sample.com:389/DC=sample,DC=com")
//                    .managerDn("CN=Admin Guy,OU=Admin Group,OU=Authorization Groups,DC=sample,DC=com")
//                    .managerPassword("secretPW");
    }
    
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        
        http
            // disable spring security default custom headers
            // our custom headers are set in SimpleCORSFilter
            .headers().disable()

            .addFilterAfter(simpleCORSFilter, HeaderWriterFilter.class)
            .addFilterBefore(authFilter, LogoutFilter.class)
        
            // This disables the built in Cross Site Request Forgery support. 
            // This is used in a html login form but since we do not have that 
            // we need to disable this support.
            .csrf().disable()
            
            .formLogin()
                .successHandler(new CustomAuthenticationSuccessHandler())
                .loginProcessingUrl("/login")
            
            .and()
            
            // not used in Web API
            //.logout()
            //    .logoutSuccessUrl("/logout")
            //
            //.and()
            
            // This tells the application not to create sessions in keeping with our stateless application.
            .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            
            .and()
            
            // This adds custom handlers for authentication and authorization.
            .exceptionHandling()
                .accessDeniedHandler(new CustomAccessDeniedHandler())
                .authenticationEntryPoint(new CustomAuthenticationEntryPoint())
                
            .and()
            
            // this is the heart of our security. This decides what requests should require what role.
            .authorizeRequests()
                // Pre-flight(AJAX) request
                .antMatchers(HttpMethod.OPTIONS, "/**").permitAll()
                
                // Login
                .antMatchers(HttpMethod.POST, "/login").permitAll()
                //.antMatchers(HttpMethod.POST, "/logout").authenticated()
                
                // Home Controller
                .antMatchers(HttpMethod.GET, "/").permitAll()
                .antMatchers(HttpMethod.GET, "/user").authenticated()
                .antMatchers(HttpMethod.GET, "/manager").hasAnyRole(MANAGER,ADMIN)
                .antMatchers(HttpMethod.GET, "/admin").hasRole(ADMIN)
                //.antMatchers(HttpMethod.GET, "/**").hasRole("USER")
                //.antMatchers(HttpMethod.POST, "/**").hasRole("ADMIN")
                //.antMatchers(HttpMethod.DELETE, "/**").hasRole("ADMIN")
                
                // Others
                .anyRequest().denyAll();
    }
    
    // Define authorization failure response
    private static class CustomAccessDeniedHandler implements AccessDeniedHandler {
        @Override
        public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException) throws IOException, ServletException {

            response.setCharacterEncoding("UTF-8");
            response.setContentType("application/json");
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            PrintWriter out = response.getWriter();
            out.print(ACCESS_DENIED_JSON);
            out.flush();
            out.close();
        }
    }
 
    // Define authentication failure response in login process
    // (also handle AJAX Preflight(OPTIONS) request)
    private static class CustomAuthenticationEntryPoint implements AuthenticationEntryPoint {
        
        public CustomAuthenticationEntryPoint() {
            super();
        }
 
        @Override
        public void commence(final HttpServletRequest request, final HttpServletResponse response, final AuthenticationException authException) throws IOException, ServletException {
 
            if (isPreflight(request)) {
                response.setStatus(HttpServletResponse.SC_NO_CONTENT);
            }
            else {
                response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Unauthorized");
                PrintWriter out = response.getWriter();
                out.print(UNAUTHORIZED_JSON);
                out.flush();
                out.close();
            }
        }
 
        // Checks if this is a X-domain pre-flight request (AJAX call)
        private boolean isPreflight(HttpServletRequest request) {
            return HttpMethod.OPTIONS.equals(request.getMethod());
        }
    }
    
    // Define successful authentication response after login
    // The authentication success handler is only called
    // when the client successfully authenticates.
    private static class CustomAuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {
        
        @Override
        public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                            Authentication authentication) throws ServletException, IOException {
            
            Authentication auth = SecurityContextHolder.getContext().getAuthentication();
            
            // get logged in username
            String username = auth.getName().toLowerCase();
            
            // get roles
            Collection<SimpleGrantedAuthority> authorities = new ArrayList<SimpleGrantedAuthority>();
            for (Object obj: auth.getAuthorities()) {
                if (obj instanceof SimpleGrantedAuthority) {
                    authorities.add((SimpleGrantedAuthority) obj);
                }
            }
            
            String token = AuthUtil.createAuthToken(username, authorities);
            ObjectMapper mapper = new ObjectMapper();
            ObjectNode node = mapper.createObjectNode().put("token", token);
            response.setCharacterEncoding("UTF-8");
            response.setContentType("application/json");
            PrintWriter out = response.getWriter();
            out.print(node.toString());
            out.flush();
            out.close();
            clearAuthenticationAttributes(request);
        }
    }
}
