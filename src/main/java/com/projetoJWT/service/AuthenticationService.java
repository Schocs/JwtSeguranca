package com.projetoJWT.service;

import com.projetoJWT.model.Usuario;
import com.projetoJWT.repository.UsuarioRepository;
import com.projetoJWT.responserequest.AuthenticationRequest;
import com.projetoJWT.responserequest.AuthenticationResponse;
import com.projetoJWT.responserequest.RegisterRequest;
import com.projetoJWT.security.Role;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

/**
 * Classe responsável pelos serviços de registro(signIn) e autenticação(logIn)
 * @author João Chocron
 */
@Service
@RequiredArgsConstructor
public class AuthenticationService {

    private final UsuarioRepository usuarioRepository;
    private final JWTService jwtService;
    private final AuthenticationManager authManager;
    private final PasswordEncoder passwordEncoder;

    /**
     * Através de um request de registro, constrói e salva um usuário na base de dados, após passar
     * pelo filtro de autenticação.
     * @param request
     * @return uma resposta de Autenticação com o JWT.
     */
    public AuthenticationResponse register(RegisterRequest request) {
        var user = Usuario.builder()
                .firstName(request.getFirstName())
                .lastName(request.getLastName())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .role(Role.USER)
                .build();
        usuarioRepository.save(user);
        var jwt = jwtService.generateToken(user);
        return AuthenticationResponse.builder()
                .token(jwt)
                .build();
    }

    /**
     * A partir de informações de login, utiliza o filtro de autenticação para verificar e autenticar
     * o request de login.
     * @param request
     * @return uma resposta de autenticação com o JWT.
     */
    public AuthenticationResponse authenticate(AuthenticationRequest request) {
        authManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getEmail(),
                        request.getPassword()
                )
        );
        var user = usuarioRepository.findByEmail(request.getEmail()).orElseThrow();
        var jwt = jwtService.generateToken(user);
        return AuthenticationResponse.builder()
                .token(jwt)
                .build();
    }
}
