package com.projetoJWT.config;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

/**
 * 'Une' o filtro de autenticação ao restante da aplicação, efetivamente
 * permitindo seu uso toda vez que uma requisição é passada.
 *
 * @author João Chocron
 *
 */
@Configuration
@RequiredArgsConstructor
@EnableWebSecurity
public class SecurityConfig {

    private final JwtAuthFilter jwtAuthFilter;
    private final AuthenticationProvider authenticationProvider;

    /**
     * Efetivamente une o filtro à aplicação com regras específicas de utilização, como a formação
     * de uma lista especial de endpoints, representados em requesMatcher e o seu padrão interno. O
     * restante dos endpoints precisarão passar pelo filtro, representado por anyRequest após o permitAll.
     * A configuração também força toda nova requisição a passar pelo filtro através de SessionCreationPolicy
     * sendo statless.
     * @param httpSecurity
     * @return a configuração de filtro de seguração de toda a aplicação
     * @throws Exception 'default' caso a build não seja possível de ser feita
     */
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {

        httpSecurity.csrf()
                .disable()
                .authorizeHttpRequests()
                .requestMatchers("/api/v1/auth/**")
                .permitAll()
                .anyRequest()
                .authenticated()
                .and()
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .authenticationProvider(authenticationProvider)
                .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class);
        return httpSecurity.build();
    }
}
