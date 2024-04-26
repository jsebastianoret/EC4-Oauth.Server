package pe.company.dto;

import java.util.List;

public record CreateUserDto(String username, String password, List<String> roles) {

}
