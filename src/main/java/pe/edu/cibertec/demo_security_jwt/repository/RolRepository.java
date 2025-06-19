package pe.edu.cibertec.demo_security_jwt.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import pe.edu.cibertec.demo_security_jwt.model.Rol;

public interface RolRepository extends JpaRepository<Rol,
        Integer> {

    Rol findByNomrol(String nomrol);
}
