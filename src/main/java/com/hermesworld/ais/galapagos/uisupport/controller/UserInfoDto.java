package com.hermesworld.ais.galapagos.uisupport.controller;

import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@JsonSerialize
public class UserInfoDto {

    private String userName;

    private String displayName;

    private String emailAddress;

    private boolean admin;

}
