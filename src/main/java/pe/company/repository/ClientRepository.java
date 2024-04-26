package pe.company.repository;

import java.util.Optional;

import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

import pe.company.model.Client;


@Repository
public interface ClientRepository extends CrudRepository<Client, Integer> {
	
	Optional<Client>findByClientId(String clientId);
	
	
	
	
	

}
