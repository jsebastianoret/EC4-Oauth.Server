package pe.company.controller;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import pe.company.dto.CreateClientDto;
import pe.company.dto.MessageDto;
import pe.company.service.ClientService;

@RestController
@RequiredArgsConstructor
@Slf4j
@RequestMapping("/client")
public class ClientController {
	
	private final ClientService clientService;
	
	@PostMapping("/create")
	public ResponseEntity<MessageDto> create(@RequestBody CreateClientDto dto){
		
		
		return ResponseEntity.status(HttpStatus.CREATED).body(clientService.create(dto));
	}

}
