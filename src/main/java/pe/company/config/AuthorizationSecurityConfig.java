package pe.company.config;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import pe.company.service.ClientService;

@Configuration
@Slf4j
@RequiredArgsConstructor	//Porque esta inmutando ??
public class AuthorizationSecurityConfig {
	
	private final PasswordEncoder passwordEncoder;
	private final ClientService clientService;
	//Hay 2 SecurityFilterChain
	//Una que usa el OAuth2Authoirization y que configura las rutas de ese
	// Y otro que configura el authorization normal
	
	
	
	
	
	//Primer SecurityFilterChain
	@Bean
	@Order(1)
	public SecurityFilterChain authSecurityFilterChain(HttpSecurity http) throws Exception{
		
		OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
		http.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
			.oidc(Customizer.withDefaults());
		
		http.exceptionHandling(exception -> exception
				.authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/login")))
				.oauth2ResourceServer((oauth2) -> oauth2.jwt(Customizer.withDefaults()));
		
		return http.build();
	}
	
	
	
	//Segundo SecurityFilterChain
	@Bean
	@Order(2)
	public SecurityFilterChain webSecurityFilterChain(HttpSecurity http) throws Exception{
		
		http.authorizeHttpRequests(auth -> auth.requestMatchers("/auth/**","/client/**").permitAll()
				.anyRequest().authenticated())
				.formLogin(Customizer.withDefaults());
		
		http.csrf(csrf->csrf.ignoringRequestMatchers("/auth/**","/client/**"));
		
		return http.build();
			
	}
	
	

	//Aqui esta la informacon que debemos poner en las pruebas, pero en este proyecto el CLIENT ya esta dentro de una Base de datos, asi que no es necesario
	/*
	@Bean
	public RegisteredClientRepository registeredClientRepository() {
		
		RegisteredClient registeredClient = RegisteredClient.withId(UUID.randomUUID().toString())
				.clientId("client")																		//Pruebas en Postman
				.clientSecret(passwordEncoder.encode("secret"))	//Cambiamos en este proeycto			//Pruebas en Postman
				.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
				.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
				.authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
				.authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
				.redirectUri("https://oauthdebugger.com/debug")											//Pruebas en Postman
				.scope(OidcScopes.OPENID)																//Prueba en el navegador
				.clientSettings(clientSettings())
				.build();
		return new InMemoryRegisteredClientRepository(registeredClient);
	}
	
	*/
	
	
	
	
	/*
			Haremos 2 pruebas, en postamn y navegador:
				>Navegador: El primer campo lo sacamos de la pagina que nos da los JSONS: "http://localhost:9000/oauth2/authorize", Luego lo demas campos de arriba
				>Postman: Usaremos los dos campos : Authorization y Body
						 	-Authorization: Podremos en Basic Auth el usuario y contraseña pero la secreta, como arriba cliente, secret
						 	-Body: Los mismos campos de arriba, pero en "code_verifier" pondremos lo que sale en el Navegador a principio, osea antes de enviar request
								   Y en "code" pondremos lo que sale despues de enviar la requets 
	*/								
	/*
	@Bean 
	public ClientSettings clientSettings() {
		
		return ClientSettings.builder().requireProofKey(true).build();
	}
	*/
	

	
	
	//ESTE METODO FUE AGREGADO PARA PODER USAR Y PROBAR EN EL PROYECTO NUEVO "resource-server"
	 @Bean
	 public OAuth2TokenCustomizer<JwtEncodingContext> tokenCustomizer(){
				return context ->{
					Authentication principal=context.getPrincipal();
					if(context.getTokenType().getValue().equals("id_token")) {
						context.getClaims().claim("token_type","id_token");
					}
					if(context.getTokenType().getValue().equals("access_token")) {
						context.getClaims().claim("token_type","access_token");
						Set<String> roles=principal.getAuthorities().stream().map(GrantedAuthority::getAuthority)
								.collect(Collectors.toSet());
						context.getClaims().claim("roles",roles).claim("username", principal.getName());
					};
				
				};
	}
	
	
	//Le damos la coneccion del servidor, nuestro servidor
	@Bean
	public AuthorizationServerSettings authorizationServerSettings() {
		
		return AuthorizationServerSettings.builder().issuer("http://localhost:9000").build();
	}
	
	
	
	
	
	
	
	
	//Estos metodos son para generar el token y contraseña
	
	@Bean
	public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
		return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
	}
	
	private KeyPair generateKeyPair() {
	
		KeyPair keyPair;
		try {
			KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
			generator.initialize(2048);
			keyPair = generator.generateKeyPair();
			
		} catch ( NoSuchAlgorithmException e) {
			throw new RuntimeException(e.getMessage());
		}
		return keyPair;
	}
	
	
	private RSAKey generateRSAKey() {
		
		KeyPair keyPair = generateKeyPair();
		RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
		RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
		return new RSAKey.Builder(publicKey).privateKey(privateKey)
				.keyID(UUID.randomUUID().toString()).build();
		
	}
	
	@Bean
	public JWKSource<SecurityContext> jwkSource(){
		RSAKey rsaKey = generateRSAKey();
		JWKSet jwkSet = new JWKSet(rsaKey);
		return (jwkSelector, securityContext) -> jwkSelector.select(jwkSet);
	}
	
	
	
	
	
	
	
	
	
	

}