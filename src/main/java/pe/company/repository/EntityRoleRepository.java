package pe.company.repository;

import java.util.Optional;

import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

import pe.company.enums.Rolename;
import pe.company.model.EntityRole;

@Repository
public interface EntityRoleRepository extends CrudRepository<EntityRole, Integer> {
	
	Optional<EntityRole> findByRole(Rolename rolename);

}
