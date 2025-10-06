# Makefile for False Sharing Analysis
# 컴파일러 설정
CXX = g++
CLANG = clang++

# 프로그램 이름
TARGET = false_sharing_analysis
SOURCE = false_sharing_analysis.cpp

# 기본 컴파일 옵션
CXXFLAGS_BASE = -std=c++17 -pthread
CXXFLAGS_DEBUG = $(CXXFLAGS_BASE) -g -O0 -DDEBUG
CXXFLAGS_RELEASE = $(CXXFLAGS_BASE) -O3 -DNDEBUG -march=native
CXXFLAGS_PROFILE = $(CXXFLAGS_BASE) -O2 -g -pg

# 경고 옵션
WARNING_FLAGS = -Wall -Wextra -Wpedantic -Wno-unused-variable

# 링커 옵션
LDFLAGS = -pthread

# 기본 타겟
.PHONY: all clean run debug release profile help benchmark

all: release

# 릴리즈 빌드 (최적화된 성능 테스트용)
release: $(TARGET)
$(TARGET): $(SOURCE)
	@echo "🔨 릴리즈 빌드 (최적화 활성화)..."
	$(CXX) $(CXXFLAGS_RELEASE) $(WARNING_FLAGS) -o $@ $< $(LDFLAGS)
	@echo "✅ 빌드 완료: $@"

# 디버그 빌드
debug: $(TARGET)_debug
$(TARGET)_debug: $(SOURCE)
	@echo "🐛 디버그 빌드..."
	$(CXX) $(CXXFLAGS_DEBUG) $(WARNING_FLAGS) -o $@ $< $(LDFLAGS)
	@echo "✅ 디버그 빌드 완료: $@"

# 프로파일링 빌드
profile: $(TARGET)_profile
$(TARGET)_profile: $(SOURCE)
	@echo "📊 프로파일링 빌드..."
	$(CXX) $(CXXFLAGS_PROFILE) $(WARNING_FLAGS) -o $@ $< $(LDFLAGS)
	@echo "✅ 프로파일링 빌드 완료: $@"

# Clang 빌드 (컴파일러 비교용)
clang: $(TARGET)_clang
$(TARGET)_clang: $(SOURCE)
	@echo "🔧 Clang 빌드..."
	$(CLANG) $(CXXFLAGS_RELEASE) $(WARNING_FLAGS) -o $@ $< $(LDFLAGS)
	@echo "✅ Clang 빌드 완료: $@"

# 실행
run: $(TARGET)
	@echo "🚀 False Sharing 분석 실행..."
	@echo "=========================================="
	./$(TARGET)

# 디버그 실행
run-debug: $(TARGET)_debug
	@echo "🐛 디버그 모드 실행..."
	@echo "=========================================="
	./$(TARGET)_debug

# 프로파일링 실행
run-profile: $(TARGET)_profile
	@echo "📊 프로파일링 실행..."
	@echo "=========================================="
	./$(TARGET)_profile
	@echo "\n📈 gprof 결과 생성 중..."
	gprof $(TARGET)_profile gmon.out > profile_report.txt
	@echo "✅ 프로파일링 결과: profile_report.txt"

# 컴파일러별 성능 비교
benchmark: release clang
	@echo "🏁 컴파일러별 성능 비교..."
	@echo "\n=== GCC 결과 ==="
	time ./$(TARGET)
	@echo "\n=== Clang 결과 ==="
	time ./$(TARGET)_clang

# 시스템 정보 출력
sysinfo:
	@echo "💻 시스템 정보:"
	@echo "OS: $$(uname -s)"
	@echo "아키텍처: $$(uname -m)"
	@echo "CPU 정보:"
	@lscpu | grep -E "Model name|CPU\(s\)|Thread|Core|Socket|Cache"
	@echo "\n메모리 정보:"
	@free -h
	@echo "\n컴파일러 버전:"
	@$(CXX) --version | head -1
	@$(CLANG) --version 2>/dev/null | head -1 || echo "Clang 미설치"

# 캐시 라인 크기 확인
cache-info:
	@echo "🗄️ 캐시 정보:"
	@echo "L1 데이터 캐시: $$(getconf LEVEL1_DCACHE_LINESIZE 2>/dev/null || echo '확인 불가') bytes"
	@echo "L2 캐시: $$(getconf LEVEL2_CACHE_LINESIZE 2>/dev/null || echo '확인 불가') bytes"
	@echo "L3 캐시: $$(getconf LEVEL3_CACHE_LINESIZE 2>/dev/null || echo '확인 불가') bytes"
	@if [ -f /proc/cpuinfo ]; then \
		echo "CPU 캐시 정보:"; \
		grep "cache size\|cache_alignment" /proc/cpuinfo | head -5; \
	fi

# 메모리 분석 (valgrind 사용)
memcheck: debug
	@echo "🔍 메모리 누수 검사..."
	@which valgrind > /dev/null || (echo "❌ valgrind가 설치되지 않음" && exit 1)
	valgrind --tool=memcheck --leak-check=full --show-leak-kinds=all ./$(TARGET)_debug

# 캐시 분석 (valgrind cachegrind 사용)
cachecheck: release
	@echo "🗄️ 캐시 성능 분석..."
	@which valgrind > /dev/null || (echo "❌ valgrind가 설치되지 않음" && exit 1)
	valgrind --tool=cachegrind ./$(TARGET)

# 성능 프로파일링 (perf 사용)
perf-analysis: release
	@echo "📈 perf를 이용한 성능 분석..."
	@which perf > /dev/null || (echo "❌ perf가 설치되지 않음 (apt install linux-tools-generic)" && exit 1)
	@echo "캐시 미스 분석:"
	perf stat -e cache-misses,cache-references,instructions,cycles ./$(TARGET)

# 다양한 최적화 레벨 테스트
optimization-test: $(SOURCE)
	@echo "⚡ 최적화 레벨별 성능 테스트..."
	@for opt in O0 O1 O2 O3 Ofast; do \
		echo "\n=== -$$opt 빌드 ==="; \
		$(CXX) $(CXXFLAGS_BASE) -$$opt $(WARNING_FLAGS) -o $(TARGET)_$$opt $(SOURCE) $(LDFLAGS); \
		echo "실행 시간:"; \
		time ./$(TARGET)_$$opt > /dev/null; \
	done
	@echo "\n🧹 임시 파일 정리..."
	@rm -f $(TARGET)_O*

# 소스 코드 생성 (개발용)
generate-source:
	@echo "📝 소스 코드 파일 생성..."
	@if [ ! -f $(SOURCE) ]; then \
		echo "$(SOURCE) 파일을 생성하세요."; \
		echo "위에서 제공된 C++ 코드를 $(SOURCE) 파일로 저장하세요."; \
	else \
		echo "✅ $(SOURCE) 파일이 이미 존재합니다."; \
	fi

# 정리
clean:
	@echo "🧹 빌드 파일 정리..."
	rm -f $(TARGET) $(TARGET)_debug $(TARGET)_profile $(TARGET)_clang
	rm -f $(TARGET)_O* gmon.out profile_report.txt
	rm -f *.o *.a *.so core
	@echo "✅ 정리 완료"

# 도움말
help:
	@echo "📚 False Sharing Analysis Makefile 사용법"
	@echo ""
	@echo "주요 타겟:"
	@echo "  make              - 릴리즈 빌드 (기본)"
	@echo "  make run          - 프로그램 실행"
	@echo "  make debug        - 디버그 빌드"
	@echo "  make run-debug    - 디버그 모드 실행"
	@echo "  make profile      - 프로파일링 빌드"
	@echo "  make run-profile  - 프로파일링 실행"
	@echo "  make clang        - Clang 컴파일러로 빌드"
	@echo "  make benchmark    - 컴파일러별 성능 비교"
	@echo ""
	@echo "분석 도구:"
	@echo "  make sysinfo          - 시스템 정보 출력"
	@echo "  make cache-info       - 캐시 정보 출력"
	@echo "  make memcheck         - 메모리 누수 검사"
	@echo "  make cachecheck       - 캐시 성능 분석"
	@echo "  make perf-analysis    - perf 성능 분석"
	@echo "  make optimization-test - 최적화 레벨 비교"
	@echo ""
	@echo "유틸리티:"
	@echo "  make clean        - 빌드 파일 정리"
	@echo "  make help         - 이 도움말 출력"
	@echo ""
	@echo "요구사항:"
	@echo "  - g++ (C++17 지원)"
	@echo "  - pthread 라이브러리"
	@echo "  - 선택사항: clang++, valgrind, perf"

# 의존성 확인
check-deps:
	@echo "🔧 의존성 확인..."
	@$(CXX) --version > /dev/null && echo "✅ g++ 사용 가능" || echo "❌ g++ 없음"
	@$(CLANG) --version > /dev/null 2>&1 && echo "✅ clang++ 사용 가능" || echo "⚠️ clang++ 없음 (선택사항)"
	@which valgrind > /dev/null 2>&1 && echo "✅ valgrind 사용 가능" || echo "⚠️ valgrind 없음 (선택사항)"
	@which perf > /dev/null 2>&1 && echo "✅ perf 사용 가능" || echo "⚠️ perf 없음 (선택사항)"
	@echo "✅ 의존성 확인 완료"