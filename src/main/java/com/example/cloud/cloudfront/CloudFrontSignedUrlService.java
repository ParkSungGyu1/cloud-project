package com.example.cloud.cloudfront;

import com.amazonaws.services.cloudfront.CloudFrontUrlSigner;
import com.amazonaws.services.cloudfront.util.SignerUtils;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;

@Service
@RequiredArgsConstructor
public class CloudFrontSignedUrlService {

    @Value("${cloudfront.domain}")
    private String cloudFrontDomain;
    @Value("${cloudfront.keyPairId}")
    private String keyPairId;

    @Value("${cloudfront.privateKeyPem}")
    private String privateKeyPem; // PKCS8 PEM 전체 문자열

    /**
     * key 예: uploads/uuid_filename.png
     */
    public String createSignedUrl(String key, Duration expiresIn) {
        try {
            // 1) PEM 문자열을 임시 파일로 저장 (SignerUtils가 File 기반 로딩을 가장 안정적으로 지원)
            Path tempKeyPath = Files.createTempFile("cf-private-", ".pem");
            Files.writeString(tempKeyPath, privateKeyPem);

            Date expiresAt = Date.from(Instant.now().plus(expiresIn));

            // 2) CloudFront가 요구하는 "resource URL" 형태로 만들기
            //    예: https://dxxx.cloudfront.net/uploads/abc.png
            String resourceUrl = normalizeDomain(cloudFrontDomain) + "/" + stripLeadingSlash(key);

            // 3) Signed URL 생성 (Canned Policy)
            return CloudFrontUrlSigner.getSignedURLWithCannedPolicy(
                    resourceUrl,
                    keyPairId,
                    SignerUtils.loadPrivateKey(tempKeyPath.toFile()),
                    expiresAt
            );
        } catch (Exception e) {
            throw new RuntimeException("CloudFront Signed URL 생성 실패", e);
        }
    }

    private String normalizeDomain(String domain) {
        // 끝의 / 제거
        if (domain.endsWith("/")) return domain.substring(0, domain.length() - 1);
        return domain;
    }

    private String stripLeadingSlash(String key) {
        if (key.startsWith("/")) return key.substring(1);
        return key;
    }
}