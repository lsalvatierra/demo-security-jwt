package pe.edu.cibertec.demo_security_jwt.repository;


import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import pe.edu.cibertec.demo_security_jwt.model.Usuario;


@Repository
public interface UsuarioRepository extends
        JpaRepository<Usuario, Integer> {


    Usuario findByNomusuario(String nomusuario);

}