package pe.company.model;


import java.util.Collection;
import java.util.Set;

import org.hibernate.annotations.ManyToAny;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import jakarta.persistence.CascadeType;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.JoinTable;
import jakarta.persistence.ManyToMany;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.Generated;
import lombok.NoArgsConstructor;

@Entity
@AllArgsConstructor
@NoArgsConstructor
@Data
@Builder
@Table(name="users")							//El archivo "UserService" que configura los modelos RolEntity y UserEntity no sera necesario crearlo, 
public class AppUser implements UserDetails {	//Aca en vez de crear un archivo con las clases UserDetailService y UserDetails aparte, mejor lo ponemos todo aca en el mismo archivo del modelo
												// E implementar sus metodos, asi seria mas facila o rapido
	
	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private Integer iduser;
	
	private String username;
	private String password;
	
	
	@ManyToMany(fetch = FetchType.EAGER, targetEntity = EntityRole.class, cascade = CascadeType.PERSIST)
	@JoinTable(name = "user_roles", joinColumns = @JoinColumn(name="iduser"), inverseJoinColumns = @JoinColumn(name="idrole"))
	private Set<EntityRole> roles;
	
	private boolean expired = false;
	private boolean locked = false;
	private boolean credentialsExpired = false;
	private boolean disable = false;

	
	
	
	@Override
	public Collection<? extends GrantedAuthority> getAuthorities() {
		
		return roles;
	}
	@Override
	public boolean isAccountNonExpired() {
		// TODO Auto-generated method stub
		return !expired;
	}
	@Override
	public boolean isAccountNonLocked() {
		// TODO Auto-generated method stub
		return !locked;
	}
	@Override
	public boolean isCredentialsNonExpired() {
		// TODO Auto-generated method stub
		return !credentialsExpired;
	}
	@Override
	public boolean isEnabled() {
		// TODO Auto-generated method stub
		return !disable;
	}
	
	

}
