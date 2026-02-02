package com.example.cloud.controller;

import com.example.cloud.dto.TeamInfoRequestDto;
import com.example.cloud.dto.TeamInfoResponseDto;
import com.example.cloud.service.TeamInfoService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.*;

@RestController
@RequiredArgsConstructor
@Slf4j
public class TeamInfoController {
    private final TeamInfoService infoService;

    @PostMapping("/api/members")
    public TeamInfoResponseDto saveMember(@RequestBody TeamInfoRequestDto requestDto){
        log.info("[API-Logging] = 멤버생성 요청 발생했습니다.");
        return infoService.saveMember(requestDto);
    }

    @GetMapping("/api/members/{id}")
    public TeamInfoResponseDto getMember(@PathVariable Long id){
        return infoService.getMember(id);
    }
}
