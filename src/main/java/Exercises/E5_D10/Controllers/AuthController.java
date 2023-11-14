package Exercises.E5_D10.Controllers;

import Exercises.E5_D10.Entities.User;
import Exercises.E5_D10.Exceptions.BadRequestException;
import Exercises.E5_D10.Payloads.NewUserDTO;
import Exercises.E5_D10.Payloads.UserLoginDTO;
import Exercises.E5_D10.Payloads.UserLoginSuccessDTO;
import Exercises.E5_D10.Services.AuthService;
import Exercises.E5_D10.Services.UsersService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.validation.BindingResult;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;

@RestController
@RequestMapping("/auth")
public class AuthController {
    @Autowired
    private AuthService authService;
    @Autowired
    private UsersService usersService;

    @PostMapping("/login")
    public UserLoginSuccessDTO login(@RequestBody UserLoginDTO body){

        return new UserLoginSuccessDTO(authService.authenticateUser(body));
    }

    @PostMapping("/register")
    @ResponseStatus(HttpStatus.CREATED) // <-- 201
    public User saveUser(@RequestBody @Validated NewUserDTO body, BindingResult validation){
        if(validation.hasErrors()){
            throw new BadRequestException(validation.getAllErrors());
        } else {
            try {
                return usersService.save(body);
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }
    }
}