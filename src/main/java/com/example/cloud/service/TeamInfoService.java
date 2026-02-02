package com.example.cloud.service;

import com.example.cloud.dto.TeamInfoRequestDto;
import com.example.cloud.dto.TeamInfoResponseDto;
import com.example.cloud.entity.TeamInfo;
import com.example.cloud.repository.TeamInfoRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class TeamInfoService {
    private final TeamInfoRepository infoRepository;

    @Transactional
    public TeamInfoResponseDto saveMember(TeamInfoRequestDto requestDto) {
        TeamInfo teamInfo = new TeamInfo(
                requestDto.getName(),
                requestDto.getAge(),
                requestDto.getMbti()
        );
        TeamInfo save = infoRepository.save(teamInfo);
        return new TeamInfoResponseDto(
                save.getId(),
                save.getName(),
                save.getAge(),
                save.getMbti()
        );
    }

    public TeamInfoResponseDto getMember(Long id) {
        TeamInfo teamInfo = infoRepository.findById(id).orElseThrow(() -> new IllegalArgumentException("존재하지 않는 id"));
        return new TeamInfoResponseDto(
                teamInfo.getId(),
                teamInfo.getName(),
                teamInfo.getAge(),
                teamInfo.getMbti()
        );
    }
}
