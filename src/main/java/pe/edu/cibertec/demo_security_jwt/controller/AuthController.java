package pe.edu.cibertec.demo_security_jwt.controller;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import pe.edu.cibertec.demo_security_jwt.dto.UsuarioSeguridadDto;
import pe.edu.cibertec.demo_security_jwt.model.Usuario;
import pe.edu.cibertec.demo_security_jwt.security.IJwtService;
import pe.edu.cibertec.demo_security_jwt.service.IUsuarioService;
import pe.edu.cibertec.demo_security_jwt.service.implement.DetalleUsuarioService;
import java.util.List;

@RestController
@RequestMapping("api/v1/auth")
public class AuthController {

    private final IUsuarioService usuarioService;
    private final DetalleUsuarioService detalleUsuarioService;
    private final AuthenticationManager authenticationManager;
    private final IJwtService jwtService;


    public AuthController(IUsuarioService usuarioService, DetalleUsuarioService detalleUsuarioService, AuthenticationManager authenticationManager, IJwtService jwtService) {
        this.usuarioService = usuarioService;
        this.detalleUsuarioService = detalleUsuarioService;
        this.authenticationManager = authenticationManager;
        this.jwtService = jwtService;
    }

    @GetMapping("/login")
    public ResponseEntity<UsuarioSeguridadDto> autenticarUsuario(
            @RequestParam String usuario,
            @RequestParam String password)
    {
            Authentication authentication =
                    authenticationManager.authenticate(
                            new UsernamePasswordAuthenticationToken(usuario,
                                    password));
            if(authentication.isAuthenticated()) {
                Usuario objUsuario = usuarioService.obtenerUsuarioxNomusuario(usuario);
                List<GrantedAuthority> authorities = detalleUsuarioService.getAuthorities(objUsuario.getRoles());
                String token = jwtService.generateToken(objUsuario, authorities);

                UsuarioSeguridadDto dto = new UsuarioSeguridadDto();
                dto.setIdusuario(objUsuario.getIdusuario());
                dto.setNomusuario(objUsuario.getNomusuario());
                dto.setToken(token);
                return ResponseEntity.ok(dto);
            }
        UsuarioSeguridadDto dto = new UsuarioSeguridadDto();
        dto.setMensajeError("Error en la autenticación");
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(dto);
    }
}
