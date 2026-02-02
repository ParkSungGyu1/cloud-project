# 1. Java 17 환경 (사용 중인 버전 확인)
FROM openjdk:17-jdk-slim

# 2. 작업 디렉토리 설정
WORKDIR /app

# 3. 빌드된 jar 파일을 컨테이너 내부로 복사
COPY build/libs/*.jar app.jar

# 4. 실행 명령어
ENTRYPOINT ["java", "-jar", "app.jar"]