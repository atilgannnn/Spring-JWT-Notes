package com.tpe.controller.dto;

import lombok.*;

import javax.validation.constraints.*;

@Data
public class LoginRequest {

    @NotBlank
    @NotNull
    private String userName;

    @NotBlank
    @NotNull
    private String password;


}
