package pe.company.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
public class BeansConfig {	//Esto solamente se encarga de codificar una contraseña
							//OSea, al guardar al modelo de la bd ya la contraseña que el cliente nos proporciono, debemos pasarle el codificado, por eso ahi invocamos esto:
							//		.password(passwordEncoder.encode(dto.password()))
	
	
	@Bean
	public PasswordEncoder passwordEncoder() {
		
		return new BCryptPasswordEncoder();
	}
	
	
	
	
	
	
	
	
}
