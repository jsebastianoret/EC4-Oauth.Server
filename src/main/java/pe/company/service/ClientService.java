package pe.company.service;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.stereotype.Service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import pe.company.dto.CreateClientDto;
import pe.company.dto.MessageDto;
import pe.company.model.Client;
import pe.company.repository.ClientRepository;

@Service
@RequiredArgsConstructor
@Slf4j
public class ClientService implements RegisteredClientRepository {
	
	private final ClientRepository clientRepository;
	private final PasswordEncoder passwordEncoder;
	
	
	public MessageDto create(CreateClientDto dto) {
		Client client = clienteFromDto(dto);
		clientRepository.save(client);
		return new MessageDto("cliente: " + client.getClientId() + " guardado con extio");
	}


	
	private Client clienteFromDto(CreateClientDto dto) {
		
		Client client = Client.builder() 
				.clientId(dto.getClientId())
				.clientSecret(passwordEncoder.encode(dto.getClientSecret()))
				.authenticationMethods(dto.getAuthenticationMethods())
				.authorizationGrantTypes(dto.getAuthorizationGrantTypes())
				.redirectUris(dto.getRedirectUris())
				.scopes(dto.getScopes())
				.requiredProofKey(dto.isRequiredProofKey())
				.build();
		
		return client; 	
	}



	@Override
	public void save(RegisteredClient registeredClient) {
		// TODO Auto-generated method stub
		
	}



	@Override
	public RegisteredClient findById(String id) {

		Client client = clientRepository.findByClientId(id)
				.orElseThrow(()-> new RuntimeException("cliente no encontrado"));
		return Client.toRegisteredClient(client);
		
	}



	@Override
	public RegisteredClient findByClientId(String clientId) {
		
		Client client = clientRepository.findByClientId(clientId)
				.orElseThrow(()-> new RuntimeException("cliente no encontrado"));
		return Client.toRegisteredClient(client);
		
	}
	
	
	
	
	
	
	

}
