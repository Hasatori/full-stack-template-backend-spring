package com.example.fullstacktemplate.dto;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class ApiResponse {
    private boolean success;
    private String message;

    public ApiResponse(boolean success, String message) {
        this.success = success;
        this.message = message;
    }
}
