package pe.edu.cibertec.demo_security_jwt.security;

import io.jsonwebtoken.Claims;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.core.GrantedAuthority;
import pe.edu.cibertec.demo_security_jwt.model.Usuario;

import java.util.List;

public interface IJwtService {
    String generateToken(Usuario usuario, List<GrantedAuthority> authorities);
    Claims parseClaims(String token);
    boolean isValid(String token);
    String extractToken(HttpServletRequest request);
    void setAuthentication(Claims claims);
}
