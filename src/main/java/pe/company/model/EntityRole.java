package pe.company.model;

import org.springframework.security.core.GrantedAuthority;

import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import pe.company.enums.Rolename;

@Entity
@AllArgsConstructor
@NoArgsConstructor
@Data
@Builder
@Table(name="roles")									//El archivo "UserService" que configura los modelos RolEntity y UserEntity no sera necesario crearlo, 
public class EntityRole implements GrantedAuthority {	//Aca en vez de crear un archivo con las clases GrantedAuthority aparte, mejor lo ponemos todo aca en el mismo archivo del modelo
														// E implementar sus metodos, asi seria mas facila o rapido
	
	private static final long serialVersionUID = 1L;
	
	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private Integer idrole;
	
	@Enumerated(EnumType.STRING)
	private Rolename role;

	
	
	
	
	@Override
	public String getAuthority() {
		
		return role.name();
	}

}
