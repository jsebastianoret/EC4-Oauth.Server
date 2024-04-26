package pe.company.controller;

import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import lombok.RequiredArgsConstructor;
import pe.company.dto.CreateUserDto;
import pe.company.dto.MessageDto;
import pe.company.service.AppUserService;

@RestController
@RequiredArgsConstructor
@RequestMapping("/auth")
public class AuthController {
	
	private final AppUserService appUserService;
	
	
	@PostMapping("/create")
	public ResponseEntity<MessageDto> createUser(@RequestBody CreateUserDto dto){
		return ResponseEntity.status(HttpStatus.CREATED).body(appUserService.createUser(dto));
	}
	
	

}
