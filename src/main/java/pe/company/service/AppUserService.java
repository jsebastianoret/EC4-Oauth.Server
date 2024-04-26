package pe.company.service;

import java.util.HashSet;
import java.util.Set;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import pe.company.dto.CreateUserDto;
import pe.company.dto.MessageDto;
import pe.company.enums.Rolename;
import pe.company.model.AppUser;
import pe.company.model.EntityRole;
import pe.company.repository.AppUserRepository;
import pe.company.repository.EntityRoleRepository;

@Service
@RequiredArgsConstructor
@Slf4j
public class AppUserService {

	private final AppUserRepository appUserRepository;
	private final EntityRoleRepository repository;
	private final PasswordEncoder passwordEncoder;
	
	
	public MessageDto createUser(CreateUserDto dto) {
		
		AppUser appUser = AppUser.builder()
				.username(dto.username())
				.password(passwordEncoder.encode(dto.password()))
				.build();
		
		Set<EntityRole> roles = new HashSet<>();
		dto.roles().forEach(r->{
			EntityRole entityRole = repository.findByRole(Rolename.valueOf(r))
					.orElseThrow(()-> new RuntimeException("el usuario no existe"));
			roles.add(entityRole);
		});
		
		appUser.setRoles(roles);
		appUserRepository.save(appUser);
		return new MessageDto("USER " + appUser.getUsername() + "guardado exitoso");
		
	}
	
	
	
	

}
