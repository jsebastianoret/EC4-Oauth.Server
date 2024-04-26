package pe.company.repository;

import java.util.Optional;

import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

import pe.company.model.AppUser;

@Repository
public interface AppUserRepository extends CrudRepository<AppUser, Integer> {
	
	Optional<AppUser> findByUsername(String username);
	

}
