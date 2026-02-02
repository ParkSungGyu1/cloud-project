package com.example.cloud.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public class TeamInfoResponseDto {
    private Long id;
    private String name;
    private int age;
    private String mbti;
}
