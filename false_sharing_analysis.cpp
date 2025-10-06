#include <atomic>
#include <iostream>
#include <thread>
#include <chrono>
#include <vector>
#include <iomanip>
#include <mutex>
#include <stdexcept>
#include <algorithm>
#include <numeric>
#include <fstream>
#include <sstream>
#include <memory>
#include <cmath>
#ifdef __linux__
#include <sched.h>
#include <unistd.h>
#endif

// 컴파일 타임 캐시 라인 크기 (대부분의 현대 CPU는 64바이트)
constexpr size_t CACHE_LINE_SIZE = 64;

// 런타임 캐시 라인 크기 감지 (검증용)
size_t get_runtime_cache_line_size() {
    static size_t cache_line_size = 0;
    if (cache_line_size == 0) {
#ifdef _SC_LEVEL1_DCACHE_LINESIZE
        long size = sysconf(_SC_LEVEL1_DCACHE_LINESIZE);
        if (size > 0) {
            cache_line_size = static_cast<size_t>(size);
        } else {
#endif
            // /proc/cpuinfo에서 cache_alignment 확인
            std::ifstream cpuinfo("/proc/cpuinfo");
            std::string line;
            while (std::getline(cpuinfo, line)) {
                if (line.find("cache_alignment") != std::string::npos) {
                    std::istringstream iss(line);
                    std::string key;
                    char colon;
                    size_t value;
                    if (iss >> key >> colon >> value && colon == ':') {
                        cache_line_size = value;
                        break;
                    }
                }
            }

            // 기본값 설정
            if (cache_line_size == 0) {
                cache_line_size = 64; // 대부분의 현대 CPU
            }
#ifdef _SC_LEVEL1_DCACHE_LINESIZE
        }
#endif
    }
    return cache_line_size;
}

// 캐시 라인 크기 가정 검증
void validate_cache_line_assumptions() {
    size_t runtime_size = get_runtime_cache_line_size();
    if (runtime_size != CACHE_LINE_SIZE) {
        std::cout << "⚠️  캐시 라인 크기 불일치:\n";
        std::cout << "   컴파일 타임: " << CACHE_LINE_SIZE << " bytes\n";
        std::cout << "   런타임 감지: " << runtime_size << " bytes\n";
        std::cout << "   → 성능 결과에 영향을 줄 수 있습니다\n\n";
    } else {
        std::cout << "✅ 캐시 라인 크기 일치: " << CACHE_LINE_SIZE << " bytes\n";
    }
}

// False Sharing이 발생하는 구조체 (의도적으로 문제가 있는 설계)
// 모든 atomic 변수가 하나의 캐시 라인에 모여있어 False Sharing 유발
struct AtomicQueueStats {
    std::atomic<uint64_t> write_attempts{0};      // 8바이트
    std::atomic<uint64_t> packets_written{0};     // 8바이트
    std::atomic<uint64_t> total_bytes_written{0}; // 8바이트
    std::atomic<uint64_t> packets_read{0};        // 8바이트
    std::atomic<uint64_t> packet_drops{0};        // 8바이트
    std::atomic<uint64_t> last_write_time{0};     // 8바이트
    std::atomic<uint64_t> max_latency_ns{0};      // 8바이트
    // 총 56바이트 - 하나의 캐시 라인(64바이트) 안에 모두 들어감
    // 이로 인해 서로 다른 스레드가 다른 멤버를 수정할 때 False Sharing 발생
};

// Lock 기반 구조체 (64바이트 정렬 없음)
struct LockBasedQueueStats {
    uint64_t write_attempts{0};      // 8바이트
    uint64_t packets_written{0};     // 8바이트
    uint64_t total_bytes_written{0}; // 8바이트
    uint64_t packets_read{0};        // 8바이트
    uint64_t packet_drops{0};        // 8바이트
    uint64_t last_write_time{0};     // 8바이트
    uint64_t max_latency_ns{0};      // 8바이트
    // 총 56바이트 - 일반적인 메모리 배치
};

// False Sharing 해결을 위한 개별 캐시 라인 정렬
struct alignas(CACHE_LINE_SIZE) AlignedAtomic {
    std::atomic<uint64_t> value{0};
    // CACHE_LINE_SIZE 정렬으로 패딩 제공
    char padding[CACHE_LINE_SIZE - sizeof(std::atomic<uint64_t>)];

    AlignedAtomic() = default;
    AlignedAtomic(uint64_t initial_value) : value(initial_value) {}

    // 복사 생성자 및 대입 연산자 정의
    AlignedAtomic(const AlignedAtomic& other) : value(other.value.load()) {}
    AlignedAtomic& operator=(const AlignedAtomic& other) {
        if (this != &other) {
            value.store(other.value.load());
        }
        return *this;
    }

    // 이동 생성자 및 대입 연산자
    AlignedAtomic(AlignedAtomic&& other) noexcept : value(other.value.load()) {}
    AlignedAtomic& operator=(AlignedAtomic&& other) noexcept {
        if (this != &other) {
            value.store(other.value.load());
        }
        return *this;
    }
};

struct NoFalseSharingStats {
    AlignedAtomic write_attempts;      // 64바이트 캐시 라인 1
    AlignedAtomic packets_written;     // 64바이트 캐시 라인 2
    AlignedAtomic total_bytes_written; // 64바이트 캐시 라인 3
    AlignedAtomic packets_read;        // 64바이트 캐시 라인 4
    AlignedAtomic packet_drops;        // 64바이트 캐시 라인 5
    AlignedAtomic last_write_time;     // 64바이트 캐시 라인 6
    AlignedAtomic max_latency_ns;      // 64바이트 캐시 라인 7
};

// CPU 친화성 설정 유틸리티
class CPUAffinity {
public:
    static bool set_thread_affinity(int cpu_id) {
#ifdef __linux__
        cpu_set_t cpuset;
        CPU_ZERO(&cpuset);
        CPU_SET(cpu_id, &cpuset);
        return pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset) == 0;
#else
        return false; // 리눅스가 아닌 경우 지원하지 않음
#endif
    }

    static int get_cpu_count() {
        return std::thread::hardware_concurrency();
    }

    static void distribute_threads(std::vector<std::thread>& threads) {
        int cpu_count = get_cpu_count();
        for (size_t i = 0; i < threads.size(); ++i) {
#ifdef __linux__
            cpu_set_t cpuset;
            CPU_ZERO(&cpuset);
            CPU_SET(i % cpu_count, &cpuset);
            pthread_setaffinity_np(threads[i].native_handle(), sizeof(cpu_set_t), &cpuset);
#endif
        }
    }
};

// 성능 측정 결과 구조체
struct BenchmarkResult {
    std::chrono::microseconds duration;
    double ops_per_second;
    size_t iterations;
    size_t thread_count;
    std::string test_name;

    // 통계 정보
    std::vector<std::chrono::microseconds> individual_runs;
    double mean_duration = 0.0;
    double std_deviation = 0.0;
    std::chrono::microseconds min_duration{0};
    std::chrono::microseconds max_duration{0};

    void calculate_statistics() {
        if (individual_runs.empty()) return;

        // 평균 계산
        double sum = std::accumulate(individual_runs.begin(), individual_runs.end(), 0.0,
            [](double acc, const auto& dur) { return acc + dur.count(); });
        mean_duration = sum / individual_runs.size();

        // 표준편차 계산
        double sq_sum = std::accumulate(individual_runs.begin(), individual_runs.end(), 0.0,
            [this](double acc, const auto& dur) {
                double diff = dur.count() - mean_duration;
                return acc + diff * diff;
            });
        std_deviation = std::sqrt(sq_sum / individual_runs.size());

        // 최소/최대값
        auto minmax = std::minmax_element(individual_runs.begin(), individual_runs.end());
        min_duration = *minmax.first;
        max_duration = *minmax.second;
    }

    void print_statistics() const {
        std::cout << "\n=== " << test_name << " 통계 분석 ===\n";
        std::cout << std::fixed << std::setprecision(2);
        std::cout << "평균 시간: " << mean_duration << " μs\n";
        std::cout << "표준편차: " << std_deviation << " μs\n";
        std::cout << "최소 시간: " << min_duration.count() << " μs\n";
        std::cout << "최대 시간: " << max_duration.count() << " μs\n";
        std::cout << "실행 횟수: " << individual_runs.size() << "\n";
        if (std_deviation > 0) {
            std::cout << "대조계수 (CV): " << (std_deviation / mean_duration * 100) << "%\n";
        }
    }
};

// 메모리 레이아웃 분석 유틸리티
class MemoryLayoutAnalyzer {
public:
    template<typename T>
    static void analyze_struct_layout(const T& obj, const std::string& struct_name) {
        std::cout << "\n=== " << struct_name << " 메모리 레이아웃 분석 ===\n";
        std::cout << "구조체 크기: " << sizeof(T) << " bytes\n";
        std::cout << "캐시 라인 크기: " << get_runtime_cache_line_size() << " bytes\n";

        uintptr_t base_addr = reinterpret_cast<uintptr_t>(&obj);
        std::cout << "기본 주소: 0x" << std::hex << base_addr;
        std::cout << " (캐시라인: " << std::dec << (base_addr / get_runtime_cache_line_size()) << ")\n";

        // 정렬 확인
        if (base_addr % get_runtime_cache_line_size() == 0) {
            std::cout << "✅ 캐시 라인 정렬됨\n";
        } else {
            std::cout << "⚠️  캐시 라인 정렬 안됨 (오프셋: "
                      << (base_addr % get_runtime_cache_line_size()) << " bytes)\n";
        }
    }

    static void check_false_sharing_risk(uintptr_t addr1, uintptr_t addr2,
                                        const std::string& var1_name,
                                        const std::string& var2_name) {
        uint64_t cache_line1 = addr1 / get_runtime_cache_line_size();
        uint64_t cache_line2 = addr2 / get_runtime_cache_line_size();

        if (cache_line1 == cache_line2) {
            std::cout << "⚠️  False Sharing 위험: " << var1_name << "와 " << var2_name
                      << "이 동일 캐시 라인(" << cache_line1 << ")에 위치\n";
        } else {
            std::cout << "✅ False Sharing 안전: " << var1_name << "(캐시라인 "
                      << cache_line1 << "), " << var2_name << "(캐시라인 "
                      << cache_line2 << ")\n";
        }
    }
};

// False Sharing이 있는 큐 클래스
class AtomicPacketQueue {
private:
    alignas(CACHE_LINE_SIZE) AtomicQueueStats stats_;

public:
    void analyze_memory_layout() {
        MemoryLayoutAnalyzer::analyze_struct_layout(stats_, "AtomicPacketQueue::AtomicQueueStats");

        // 각 멤버의 주소 분석
        uintptr_t write_attempts_addr = reinterpret_cast<uintptr_t>(&stats_.write_attempts);
        uintptr_t packets_written_addr = reinterpret_cast<uintptr_t>(&stats_.packets_written);
        uintptr_t total_bytes_addr = reinterpret_cast<uintptr_t>(&stats_.total_bytes_written);
        uintptr_t packets_read_addr = reinterpret_cast<uintptr_t>(&stats_.packets_read);
        uintptr_t packet_drops_addr = reinterpret_cast<uintptr_t>(&stats_.packet_drops);

        std::cout << "\n멤버별 주소 및 캐시 라인:\n";
        std::cout << "  write_attempts:      0x" << std::hex << std::setw(12) << write_attempts_addr
                  << " (캐시라인: " << std::dec << (write_attempts_addr / get_runtime_cache_line_size()) << ")\n";
        std::cout << "  packets_written:     0x" << std::hex << std::setw(12) << packets_written_addr
                  << " (캐시라인: " << std::dec << (packets_written_addr / get_runtime_cache_line_size()) << ")\n";
        std::cout << "  total_bytes_written: 0x" << std::hex << std::setw(12) << total_bytes_addr
                  << " (캐시라인: " << std::dec << (total_bytes_addr / get_runtime_cache_line_size()) << ")\n";
        std::cout << "  packets_read:        0x" << std::hex << std::setw(12) << packets_read_addr
                  << " (캐시라인: " << std::dec << (packets_read_addr / get_runtime_cache_line_size()) << ")\n";
        std::cout << "  packet_drops:        0x" << std::hex << std::setw(12) << packet_drops_addr
                  << " (캐시라인: " << std::dec << (packet_drops_addr / get_runtime_cache_line_size()) << ")\n";

        // False Sharing 위험도 분석
        uint64_t write_attempts_cache_line = write_attempts_addr / get_runtime_cache_line_size();
        uint64_t packets_read_cache_line = packets_read_addr / get_runtime_cache_line_size();
        uint64_t packets_written_cache_line = packets_written_addr / get_runtime_cache_line_size();
        uint64_t packet_drops_cache_line = packet_drops_addr / get_runtime_cache_line_size();

        bool false_sharing_detected = (write_attempts_cache_line == packets_read_cache_line) ||
                                     (packets_written_cache_line == packet_drops_cache_line);

        std::cout << "\n⚠️  False Sharing 위험: " << (false_sharing_detected ? "있음" : "없음") << "\n";

        if (false_sharing_detected) {
            std::cout << "   🔴 모든 멤버가 동일한 캐시 라인에 위치\n";
            std::cout << "   → Writer 스레드 (write_attempts, packets_written): 캐시라인 " << write_attempts_cache_line << "\n";
            std::cout << "   → Reader 스레드 (packets_read, packet_drops): 캐시라인 " << packets_read_cache_line << "\n";
            std::cout << "   → 여러 스레드가 다른 멤버를 동시 수정 시 캐시 라인 경합 발생\n";
            std::cout << "   → 메모리 버스 충돌로 인한 성능 저하 예상\n";
            std::cout << "   → 캐시 일관성 프로토콜 오버헤드 증가\n";
        } else {
            std::cout << "   ✅ 예상과 다르게 False Sharing이 발생하지 않았습니다\n";
            std::cout << "   → 구조체 크기나 정렬이 예상과 다를 수 있습니다\n";
        }
    }

    // 예외 처리가 강화된 업데이트 메서드들
    void update_write_stats(size_t bytes) noexcept {
        try {
            // 배리어 전에 오버플로우 검사
            if (stats_.write_attempts.load(std::memory_order_relaxed) == UINT64_MAX) {
                std::cerr << "Warning: write_attempts counter overflow\n";
                return;
            }

            stats_.write_attempts.fetch_add(1, std::memory_order_relaxed);
            stats_.packets_written.fetch_add(1, std::memory_order_relaxed);

            // bytes 오버플로우 검사
            uint64_t current_total = stats_.total_bytes_written.load(std::memory_order_relaxed);
            if (current_total > UINT64_MAX - bytes) {
                std::cerr << "Warning: total_bytes_written overflow prevented\n";
                return;
            }

            stats_.total_bytes_written.fetch_add(bytes, std::memory_order_relaxed);

            // 타임스탬프 업데이트
            auto now = std::chrono::high_resolution_clock::now();
            auto timestamp = std::chrono::duration_cast<std::chrono::nanoseconds>(now.time_since_epoch()).count();
            stats_.last_write_time.store(timestamp, std::memory_order_relaxed);
        } catch (const std::exception& e) {
            std::cerr << "Exception in update_write_stats: " << e.what() << "\n";
        } catch (...) {
            std::cerr << "Unknown exception in update_write_stats\n";
        }
    }

    void update_read_stats() noexcept {
        try {
            if (stats_.packets_read.load(std::memory_order_relaxed) == UINT64_MAX) {
                std::cerr << "Warning: packets_read counter overflow\n";
                return;
            }
            stats_.packets_read.fetch_add(1, std::memory_order_relaxed);
        } catch (const std::exception& e) {
            std::cerr << "Exception in update_read_stats: " << e.what() << "\n";
        } catch (...) {
            std::cerr << "Unknown exception in update_read_stats\n";
        }
    }

    void update_drop_stats() noexcept {
        try {
            if (stats_.packet_drops.load(std::memory_order_relaxed) == UINT64_MAX) {
                std::cerr << "Warning: packet_drops counter overflow\n";
                return;
            }
            stats_.packet_drops.fetch_add(1, std::memory_order_relaxed);
        } catch (const std::exception& e) {
            std::cerr << "Exception in update_drop_stats: " << e.what() << "\n";
        } catch (...) {
            std::cerr << "Unknown exception in update_drop_stats\n";
        }
    }

    uint64_t get_total_packets() const noexcept {
        try {
            return stats_.packets_written.load(std::memory_order_relaxed) +
                   stats_.packets_read.load(std::memory_order_relaxed);
        } catch (...) {
            std::cerr << "Exception in get_total_packets, returning 0\n";
            return 0;
        }
    }

    // 시스템 상태 검증 메서드
    bool validate_state() const noexcept {
        try {
            uint64_t write_attempts = stats_.write_attempts.load(std::memory_order_relaxed);
            uint64_t packets_written = stats_.packets_written.load(std::memory_order_relaxed);
            uint64_t packets_read = stats_.packets_read.load(std::memory_order_relaxed);
            uint64_t packet_drops = stats_.packet_drops.load(std::memory_order_relaxed);

            // 논리적 일관성 검사
            if (packets_written > write_attempts) {
                std::cerr << "Validation error: packets_written > write_attempts\n";
                return false;
            }

            // 오버플로우 검사
            if (write_attempts == UINT64_MAX || packets_written == UINT64_MAX ||
                packets_read == UINT64_MAX || packet_drops == UINT64_MAX) {
                std::cerr << "Validation error: Counter overflow detected\n";
                return false;
            }

            return true;
        } catch (...) {
            std::cerr << "Exception during state validation\n";
            return false;
        }
    }
};

// Lock 기반 큐 클래스 (예외 처리 강화)
class LockBasedQueue {
private:
    LockBasedQueueStats stats_;
    mutable std::mutex stats_mutex_;  // 통계 보호용 뮤텍스
    std::atomic<bool> is_valid_{true}; // 객체 상태 추적

public:
    LockBasedQueue() = default;
    ~LockBasedQueue() {
        is_valid_.store(false, std::memory_order_release);
    }

    // 복사 및 이동 생성자 비활성화 (thread-safety)
    LockBasedQueue(const LockBasedQueue&) = delete;
    LockBasedQueue& operator=(const LockBasedQueue&) = delete;
    LockBasedQueue(LockBasedQueue&&) = delete;
    LockBasedQueue& operator=(LockBasedQueue&&) = delete;

    void analyze_memory_layout() {
        MemoryLayoutAnalyzer::analyze_struct_layout(stats_, "LockBasedQueue::LockBasedQueueStats");

        // 각 멤버의 주소 분석
        uintptr_t mutex_addr = reinterpret_cast<uintptr_t>(&stats_mutex_);
        uintptr_t write_attempts_addr = reinterpret_cast<uintptr_t>(&stats_.write_attempts);
        uintptr_t packets_read_addr = reinterpret_cast<uintptr_t>(&stats_.packets_read);

        std::cout << "\n추가 정보:\n";
        std::cout << "std::mutex 크기: " << sizeof(std::mutex) << " bytes\n";
        std::cout << "전체 객체 크기: " << sizeof(LockBasedQueue) << " bytes\n";
        std::cout << "뮤텍스 주소: 0x" << std::hex << mutex_addr
                  << " (캐시라인: " << std::dec << (mutex_addr / get_runtime_cache_line_size()) << ")\n";

        std::cout << "\n🔒 Lock 기반 동기화 특징:\n";
        std::cout << "   ✅ Thread-safe: 뮤텍스로 전체 구조체 보호\n";
        std::cout << "   ✅ False Sharing 없음: 직렬화로 동시 접근 방지\n";
        std::cout << "   ⚠️  성능: 직렬화로 인한 오버헤드\n";
        std::cout << "   ℹ️  메모리: 일반적인 배치 (정렬 없음)\n";
    }

    void update_write_stats(size_t bytes) noexcept {
        if (!is_valid_.load(std::memory_order_acquire)) {
            std::cerr << "Warning: Operating on invalid LockBasedQueue\n";
            return;
        }

        try {
            std::lock_guard<std::mutex> lock(stats_mutex_);

            // 오버플로우 검사
            if (stats_.write_attempts == UINT64_MAX) {
                std::cerr << "Warning: write_attempts counter overflow\n";
                return;
            }
            if (stats_.total_bytes_written > UINT64_MAX - bytes) {
                std::cerr << "Warning: total_bytes_written overflow prevented\n";
                return;
            }

            stats_.write_attempts++;
            stats_.packets_written++;
            stats_.total_bytes_written += bytes;

            // 타임스탬프 업데이트
            auto now = std::chrono::high_resolution_clock::now();
            auto timestamp = std::chrono::duration_cast<std::chrono::nanoseconds>(now.time_since_epoch()).count();
            stats_.last_write_time = timestamp;
        } catch (const std::system_error& e) {
            std::cerr << "Mutex error in update_write_stats: " << e.what() << "\n";
        } catch (const std::exception& e) {
            std::cerr << "Exception in update_write_stats: " << e.what() << "\n";
        } catch (...) {
            std::cerr << "Unknown exception in update_write_stats\n";
        }
    }

    void update_read_stats() noexcept {
        if (!is_valid_.load(std::memory_order_acquire)) return;

        try {
            std::lock_guard<std::mutex> lock(stats_mutex_);
            if (stats_.packets_read == UINT64_MAX) {
                std::cerr << "Warning: packets_read counter overflow\n";
                return;
            }
            stats_.packets_read++;
        } catch (const std::exception& e) {
            std::cerr << "Exception in update_read_stats: " << e.what() << "\n";
        } catch (...) {
            std::cerr << "Unknown exception in update_read_stats\n";
        }
    }

    void update_drop_stats() noexcept {
        if (!is_valid_.load(std::memory_order_acquire)) return;

        try {
            std::lock_guard<std::mutex> lock(stats_mutex_);
            if (stats_.packet_drops == UINT64_MAX) {
                std::cerr << "Warning: packet_drops counter overflow\n";
                return;
            }
            stats_.packet_drops++;
        } catch (const std::exception& e) {
            std::cerr << "Exception in update_drop_stats: " << e.what() << "\n";
        } catch (...) {
            std::cerr << "Unknown exception in update_drop_stats\n";
        }
    }

    uint64_t get_total_packets() const noexcept {
        if (!is_valid_.load(std::memory_order_acquire)) return 0;

        try {
            std::lock_guard<std::mutex> lock(stats_mutex_);
            return stats_.packets_written + stats_.packets_read;
        } catch (const std::exception& e) {
            std::cerr << "Exception in get_total_packets: " << e.what() << "\n";
            return 0;
        } catch (...) {
            std::cerr << "Unknown exception in get_total_packets\n";
            return 0;
        }
    }

    // 추가적인 유틸리티 메서드
    bool is_valid() const noexcept {
        return is_valid_.load(std::memory_order_acquire);
    }

    void reset_stats() noexcept {
        if (!is_valid()) return;
        try {
            std::lock_guard<std::mutex> lock(stats_mutex_);
            stats_ = LockBasedQueueStats{};
        } catch (...) {
            std::cerr << "Exception in reset_stats\n";
        }
    }
};
// False Sharing이 없는 큐 클래스 (최적화된 성능)
class NoFalseSharingQueue {
private:
    NoFalseSharingStats stats_;
    std::atomic<bool> is_valid_{true};

public:
    NoFalseSharingQueue() = default;
    ~NoFalseSharingQueue() {
        is_valid_.store(false, std::memory_order_release);
    }

    // 복사 및 이동 생성자 (atomic 변수들로 인해 복잡하지만 구현)
    NoFalseSharingQueue(const NoFalseSharingQueue& other) {
        copy_stats_from(other);
    }

    NoFalseSharingQueue& operator=(const NoFalseSharingQueue& other) {
        if (this != &other) {
            copy_stats_from(other);
        }
        return *this;
    }

    NoFalseSharingQueue(NoFalseSharingQueue&& other) noexcept {
        copy_stats_from(other);
    }

    NoFalseSharingQueue& operator=(NoFalseSharingQueue&& other) noexcept {
        if (this != &other) {
            copy_stats_from(other);
        }
        return *this;
    }

    void analyze_memory_layout() {
        MemoryLayoutAnalyzer::analyze_struct_layout(stats_, "NoFalseSharingQueue::NoFalseSharingStats");

        // 각 멤버의 주소 분석
        uintptr_t write_attempts_addr = reinterpret_cast<uintptr_t>(&stats_.write_attempts);
        uintptr_t packets_written_addr = reinterpret_cast<uintptr_t>(&stats_.packets_written);
        uintptr_t total_bytes_addr = reinterpret_cast<uintptr_t>(&stats_.total_bytes_written);
        uintptr_t packets_read_addr = reinterpret_cast<uintptr_t>(&stats_.packets_read);
        uintptr_t packet_drops_addr = reinterpret_cast<uintptr_t>(&stats_.packet_drops);

        std::cout << "\n멤버별 주소 및 캐시 라인:\n";
        std::cout << "  write_attempts:      0x" << std::hex << std::setw(12) << write_attempts_addr
                  << " (캐시라인: " << std::dec << (write_attempts_addr / get_runtime_cache_line_size()) << ")\n";
        std::cout << "  packets_written:     0x" << std::hex << std::setw(12) << packets_written_addr
                  << " (캐시라인: " << std::dec << (packets_written_addr / get_runtime_cache_line_size()) << ")\n";
        std::cout << "  total_bytes_written: 0x" << std::hex << std::setw(12) << total_bytes_addr
                  << " (캐시라인: " << std::dec << (total_bytes_addr / get_runtime_cache_line_size()) << ")\n";
        std::cout << "  packets_read:        0x" << std::hex << std::setw(12) << packets_read_addr
                  << " (캐시라인: " << std::dec << (packets_read_addr / get_runtime_cache_line_size()) << ")\n";
        std::cout << "  packet_drops:        0x" << std::hex << std::setw(12) << packet_drops_addr
                  << " (캐시라인: " << std::dec << (packet_drops_addr / get_runtime_cache_line_size()) << ")\n";

        // False Sharing 검증
        verify_no_false_sharing();

        std::cout << "\n✅ 최적화 특징:\n";
        std::cout << "   ✅ False Sharing 없음: 각 멤버가 독립 캐시 라인\n";
        std::cout << "   ✅ 높은 동시성: Lock-free atomic 오퍼레이션\n";
        std::cout << "   ⚠️  메모리 사용량: " << sizeof(NoFalseSharingStats) << " bytes (일반 대비 "
                  << (sizeof(NoFalseSharingStats) / sizeof(AtomicQueueStats)) << "x)\n";
        std::cout << "   ℹ️  적합한 사용: 고성능 네트워크 애플리케이션\n";
    }

private:
    void copy_stats_from(const NoFalseSharingQueue& other) {
        stats_.write_attempts = other.stats_.write_attempts;
        stats_.packets_written = other.stats_.packets_written;
        stats_.total_bytes_written = other.stats_.total_bytes_written;
        stats_.packets_read = other.stats_.packets_read;
        stats_.packet_drops = other.stats_.packet_drops;
        stats_.last_write_time = other.stats_.last_write_time;
        stats_.max_latency_ns = other.stats_.max_latency_ns;
        is_valid_.store(true, std::memory_order_release);
    }

    void verify_no_false_sharing() {
        std::vector<std::pair<std::string, uintptr_t>> members = {
            {"write_attempts", reinterpret_cast<uintptr_t>(&stats_.write_attempts)},
            {"packets_written", reinterpret_cast<uintptr_t>(&stats_.packets_written)},
            {"total_bytes_written", reinterpret_cast<uintptr_t>(&stats_.total_bytes_written)},
            {"packets_read", reinterpret_cast<uintptr_t>(&stats_.packets_read)},
            {"packet_drops", reinterpret_cast<uintptr_t>(&stats_.packet_drops)}
        };

        bool all_separate = true;
        size_t cache_line_size = get_runtime_cache_line_size();

        for (size_t i = 0; i < members.size(); ++i) {
            for (size_t j = i + 1; j < members.size(); ++j) {
                uint64_t cache_line1 = members[i].second / cache_line_size;
                uint64_t cache_line2 = members[j].second / cache_line_size;
                if (cache_line1 == cache_line2) {
                    std::cout << "\n⚠️  예상치 못한 False Sharing: "
                              << members[i].first << "와 " << members[j].first
                              << "이 캐시라인 " << cache_line1 << "에 위치\n";
                    all_separate = false;
                }
            }
        }

        if (all_separate) {
            std::cout << "\n✅ False Sharing 검증: 모든 멤버가 독립 캐시 라인에 위치\n";
        }
    }

public:

    void update_write_stats(size_t bytes) noexcept {
        if (!is_valid_.load(std::memory_order_acquire)) {
            return;
        }

        try {
            // 오버플로우 검사
            uint64_t current_attempts = stats_.write_attempts.value.load(std::memory_order_relaxed);
            if (current_attempts == UINT64_MAX) {
                std::cerr << "Warning: write_attempts counter overflow\n";
                return;
            }

            uint64_t current_total = stats_.total_bytes_written.value.load(std::memory_order_relaxed);
            if (current_total > UINT64_MAX - bytes) {
                std::cerr << "Warning: total_bytes_written overflow prevented\n";
                return;
            }

            // Atomic 업데이트 (각각 다른 캐시 라인에 있음)
            stats_.write_attempts.value.fetch_add(1, std::memory_order_relaxed);
            stats_.packets_written.value.fetch_add(1, std::memory_order_relaxed);
            stats_.total_bytes_written.value.fetch_add(bytes, std::memory_order_relaxed);

            // 타임스탬프 업데이트
            auto now = std::chrono::high_resolution_clock::now();
            auto timestamp = std::chrono::duration_cast<std::chrono::nanoseconds>(now.time_since_epoch()).count();
            stats_.last_write_time.value.store(timestamp, std::memory_order_relaxed);
        } catch (const std::exception& e) {
            std::cerr << "Exception in update_write_stats: " << e.what() << "\n";
        } catch (...) {
            std::cerr << "Unknown exception in update_write_stats\n";
        }
    }

    void update_read_stats() noexcept {
        if (!is_valid_.load(std::memory_order_acquire)) return;

        try {
            uint64_t current_reads = stats_.packets_read.value.load(std::memory_order_relaxed);
            if (current_reads == UINT64_MAX) {
                std::cerr << "Warning: packets_read counter overflow\n";
                return;
            }
            stats_.packets_read.value.fetch_add(1, std::memory_order_relaxed);
        } catch (const std::exception& e) {
            std::cerr << "Exception in update_read_stats: " << e.what() << "\n";
        } catch (...) {
            std::cerr << "Unknown exception in update_read_stats\n";
        }
    }

    void update_drop_stats() noexcept {
        if (!is_valid_.load(std::memory_order_acquire)) return;

        try {
            uint64_t current_drops = stats_.packet_drops.value.load(std::memory_order_relaxed);
            if (current_drops == UINT64_MAX) {
                std::cerr << "Warning: packet_drops counter overflow\n";
                return;
            }
            stats_.packet_drops.value.fetch_add(1, std::memory_order_relaxed);
        } catch (const std::exception& e) {
            std::cerr << "Exception in update_drop_stats: " << e.what() << "\n";
        } catch (...) {
            std::cerr << "Unknown exception in update_drop_stats\n";
        }
    }

    uint64_t get_total_packets() const noexcept {
        if (!is_valid_.load(std::memory_order_acquire)) return 0;

        try {
            return stats_.packets_written.value.load(std::memory_order_relaxed) +
                   stats_.packets_read.value.load(std::memory_order_relaxed);
        } catch (...) {
            std::cerr << "Exception in get_total_packets, returning 0\n";
            return 0;
        }
    }

    // 고급 유틸리티 메서드들
    bool is_valid() const noexcept {
        return is_valid_.load(std::memory_order_acquire);
    }

    void reset_stats() noexcept {
        if (!is_valid()) return;
        try {
            stats_.write_attempts.value.store(0, std::memory_order_relaxed);
            stats_.packets_written.value.store(0, std::memory_order_relaxed);
            stats_.total_bytes_written.value.store(0, std::memory_order_relaxed);
            stats_.packets_read.value.store(0, std::memory_order_relaxed);
            stats_.packet_drops.value.store(0, std::memory_order_relaxed);
            stats_.last_write_time.value.store(0, std::memory_order_relaxed);
            stats_.max_latency_ns.value.store(0, std::memory_order_relaxed);
        } catch (...) {
            std::cerr << "Exception in reset_stats\n";
        }
    }

    // 성능 메트릭 수집
    struct PerformanceMetrics {
        uint64_t write_attempts;
        uint64_t packets_written;
        uint64_t total_bytes_written;
        uint64_t packets_read;
        uint64_t packet_drops;
        uint64_t last_write_time;
        uint64_t max_latency_ns;
        double write_success_rate;
        double throughput_mbps;
    };

    PerformanceMetrics get_performance_metrics() const noexcept {
        PerformanceMetrics metrics{};
        if (!is_valid()) return metrics;

        try {
            metrics.write_attempts = stats_.write_attempts.value.load(std::memory_order_relaxed);
            metrics.packets_written = stats_.packets_written.value.load(std::memory_order_relaxed);
            metrics.total_bytes_written = stats_.total_bytes_written.value.load(std::memory_order_relaxed);
            metrics.packets_read = stats_.packets_read.value.load(std::memory_order_relaxed);
            metrics.packet_drops = stats_.packet_drops.value.load(std::memory_order_relaxed);
            metrics.last_write_time = stats_.last_write_time.value.load(std::memory_order_relaxed);
            metrics.max_latency_ns = stats_.max_latency_ns.value.load(std::memory_order_relaxed);

            // 계산된 메트릭
            if (metrics.write_attempts > 0) {
                metrics.write_success_rate = static_cast<double>(metrics.packets_written) / metrics.write_attempts * 100.0;
            }

            // 예상 처리량 (MB/s) - 시간 계산이 필요하지만 예시로 대략적인 값
            metrics.throughput_mbps = static_cast<double>(metrics.total_bytes_written) / (1024.0 * 1024.0);

        } catch (...) {
            std::cerr << "Exception in get_performance_metrics\n";
        }

        return metrics;
    }
};

// 개선된 성능 벤치마크 클래스
class EnhancedBenchmark {
public:
    template<typename QueueType>
    static BenchmarkResult benchmark_queue_enhanced(QueueType& queue, const std::string& queue_name,
                                                   int iterations, int num_threads, int runs = 5) {
        BenchmarkResult result;
        result.test_name = queue_name;
        result.iterations = iterations;
        result.thread_count = num_threads;

        std::cout << "\n=== " << queue_name << " 성능 테스트 (다중 실행) ===\n";
        std::cout << "실행 횟수: " << runs << ", 스레드: " << num_threads
                  << ", 반복: " << iterations << "\n";

        // 워밍업 라운드
        std::cout << "워밍업 중...\n";
        warmup_run(queue, iterations / 10, num_threads);

        // 다중 실행
        for (int run = 0; run < runs; ++run) {
            auto duration = single_benchmark_run(queue, iterations, num_threads);
            result.individual_runs.push_back(duration);
            std::cout << "Run " << (run + 1) << ": " << duration.count() << " μs\n";
        }

        // 통계 계산
        result.calculate_statistics();
        result.duration = std::chrono::microseconds(static_cast<long>(result.mean_duration));
        result.ops_per_second = (static_cast<double>(iterations * num_threads) / result.mean_duration * 1000000);

        return result;
    }

private:
    template<typename QueueType>
    static std::chrono::microseconds single_benchmark_run(QueueType& queue, int iterations, int num_threads) {
        auto start = std::chrono::high_resolution_clock::now();

        std::vector<std::thread> threads;
        threads.reserve(num_threads);

        // 스레드 생성 및 CPU 친화성 설정
        for (int i = 0; i < num_threads; ++i) {
            threads.emplace_back([&queue, iterations, i, num_threads]() {
                // CPU 친화성 설정
                CPUAffinity::set_thread_affinity(i % CPUAffinity::get_cpu_count());

                // 작업 로드 분산
                perform_workload(queue, iterations, i);
            });
        }

        // 스레드 대기
        for (auto& t : threads) {
            if (t.joinable()) {
                t.join();
            }
        }

        auto end = std::chrono::high_resolution_clock::now();
        return std::chrono::duration_cast<std::chrono::microseconds>(end - start);
    }

    template<typename QueueType>
    static void warmup_run(QueueType& queue, int iterations, int num_threads) {
        single_benchmark_run(queue, iterations, num_threads);
    }

    template<typename QueueType>
    static void perform_workload(QueueType& queue, int iterations, int thread_id) {
        // False Sharing을 유발하기 위해 서로 다른 멤버를 수정
        for (int j = 0; j < iterations; ++j) {
            switch (thread_id % 4) {
                case 0:
                    // Writer 스레드: write 오퍼레이션
                    queue.update_write_stats(100);
                    break;
                case 1:
                    // Reader 스레드: read 오퍼레이션
                    queue.update_read_stats();
                    break;
                case 2:
                    // Drop 스레드: drop 오퍼레이션
                    queue.update_drop_stats();
                    break;
                case 3:
                    // Reader 스레드: 읽기 전용
                    asm volatile("" : : "r"(queue.get_total_packets()) : "memory"); // 최적화 방지
                    break;
            }
        }
    }
};

// 호환성을 위한 래퍼 함수
template<typename QueueType>
auto benchmark_queue(QueueType& queue, const std::string& queue_name,
                    int iterations, int num_threads) {
    auto result = EnhancedBenchmark::benchmark_queue_enhanced(queue, queue_name, iterations, num_threads);
    std::cout << "평균 실행 시간: " << static_cast<long>(result.mean_duration) << " μs\n";
    std::cout << "초당 연산: " << std::fixed << std::setprecision(0) << result.ops_per_second << " ops/sec\n";
    return result.duration;
}

// 검증 메커니즘 클래스
class ValidationFramework {
public:
    // 시스템 환경 검증
    static bool validate_system_environment() {
        std::cout << "\n=== 시스템 환경 검증 ===\n";

        // CPU 정보 검증
        int cpu_count = std::thread::hardware_concurrency();
        std::cout << "CPU 코어 수: " << cpu_count << "\n";

        if (cpu_count < 2) {
            std::cout << "⚠️  경고: 멀티코어 시스템에서 테스트하는 것이 바람직합니다.\n";
        }

        // 캐시 라인 크기 검증
        size_t runtime_cache_line_size = get_runtime_cache_line_size();
        std::cout << "감지된 캐시 라인 크기: " << runtime_cache_line_size << " bytes\n";

        // 컴파일 타임 vs 런타임 캐시 라인 크기 검증
        validate_cache_line_assumptions();

        if (runtime_cache_line_size != 64 && runtime_cache_line_size != 128) {
            std::cout << "⚠️  경고: 비표준 캐시 라인 크기가 감지되었습니다.\n";
        }

        // 메모리 정렬 검증
        validate_memory_alignment();

        std::cout << "✅ 시스템 환경 검증 완료\n";
        return true;
    }

    // 메모리 정렬 검증
    static void validate_memory_alignment() {
        std::cout << "\n--- 메모리 정렬 검증 ---\n";

        AtomicQueueStats atomic_stats;
        NoFalseSharingStats no_sharing_stats;

        // AtomicQueueStats 정렬 검증 (컴파일 타임 정렬 사용)
        uintptr_t atomic_addr = reinterpret_cast<uintptr_t>(&atomic_stats);
        bool atomic_aligned = (atomic_addr % CACHE_LINE_SIZE) == 0;
        std::cout << "AtomicQueueStats 정렬: " << (atomic_aligned ? "✅" : "❌") << "\n";

        // NoFalseSharingStats 멤버 정렬 검증 (컴파일 타임 정렬 사용)
        uintptr_t no_sharing_addr = reinterpret_cast<uintptr_t>(&no_sharing_stats);
        bool no_sharing_aligned = (no_sharing_addr % CACHE_LINE_SIZE) == 0;
        std::cout << "NoFalseSharingStats 기본 정렬: " << (no_sharing_aligned ? "✅" : "❌") << "\n";

        // 각 AlignedAtomic 멤버의 정렬 검증 (컴파일 타임 정렬 사용)
        uintptr_t member1_addr = reinterpret_cast<uintptr_t>(&no_sharing_stats.write_attempts);
        uintptr_t member2_addr = reinterpret_cast<uintptr_t>(&no_sharing_stats.packets_written);

        bool member1_aligned = (member1_addr % CACHE_LINE_SIZE) == 0;
        bool member2_aligned = (member2_addr % CACHE_LINE_SIZE) == 0;

        std::cout << "NoFalseSharingStats 멤버 정렬: "
                  << (member1_aligned && member2_aligned ? "✅" : "❌") << "\n";
    }

    // False Sharing 검증
    template<typename QueueType>
    static bool validate_false_sharing(const QueueType& queue, const std::string& queue_name) {
        std::cout << "\n--- " << queue_name << " False Sharing 검증 ---\n";

        // 이 부분은 각 큐 타입에 따라 다르게 구현
        // AtomicPacketQueue와 NoFalseSharingQueue에 대해 다르게 처리

        return true;
    }

    // 성능 결과 검증
    static bool validate_performance_results(const std::vector<BenchmarkResult>& results) {
        std::cout << "\n=== 성능 결과 검증 ===\n";

        if (results.size() < 2) {
            std::cout << "⚠️  충분한 결과가 없어 비교할 수 없습니다.\n";
            return false;
        }

        // 예상 성능 패턴 검증
        bool validation_passed = true;

        // 1. NoFalseSharingQueue가 가장 빠르거나 경쟁력 있어야 함
        // 2. LockBasedQueue가 가장 느릴 가능성이 높음
        // 3. 결과의 일관성 검증 (표준편차가 너무 크지 않음)

        for (const auto& result : results) {
            if (result.std_deviation > result.mean_duration * 0.3) { // 30% 이상 편차
                std::cout << "⚠️  " << result.test_name
                          << ": 높은 편차 감지 (CV: "
                          << (result.std_deviation / result.mean_duration * 100) << "%)\n";
                validation_passed = false;
            }
        }

        if (validation_passed) {
            std::cout << "✅ 성능 결과 검증 통과\n";
        }

        return validation_passed;
    }
};

void run_complete_analysis() {
    // 시스템 환경 검증
    if (!ValidationFramework::validate_system_environment()) {
        std::cerr << "시스템 환경 검증 실패\n";
        return;
    }

    const int iterations = 500000; // 더 안정적인 결과를 위해 줄임
    const int num_threads = std::min(8, static_cast<int>(std::thread::hardware_concurrency()));
    const int benchmark_runs = 5; // 다중 실행

    std::cout << "\n=== 개선된 False Sharing 분석 ===\n";
    std::cout << "테스트 조건:\n";
    std::cout << "  - 반복 횟수: " << iterations << "\n";
    std::cout << "  - 스레드 수: " << num_threads << "\n";
    std::cout << "  - 벤치마크 실행 횟수: " << benchmark_runs << "\n";
    std::cout << "  - 하드웨어 스레드: " << std::thread::hardware_concurrency() << "\n";

    std::vector<BenchmarkResult> benchmark_results;

    try {
        // 1. False Sharing이 있는 Atomic 큐 테스트
        std::cout << "\n" << std::string(60, '=') << "\n";
        AtomicPacketQueue atomic_sharing_queue;
        atomic_sharing_queue.analyze_memory_layout();

        if (!atomic_sharing_queue.validate_state()) {
            throw std::runtime_error("AtomicPacketQueue validation failed");
        }

        auto result1 = EnhancedBenchmark::benchmark_queue_enhanced(
            atomic_sharing_queue, "Atomic Queue (False Sharing)", iterations, num_threads, benchmark_runs);
        result1.print_statistics();
        benchmark_results.push_back(result1);

        // 2. Lock 기반 큐 테스트
        std::cout << "\n" << std::string(60, '=') << "\n";
        LockBasedQueue lock_queue;
        lock_queue.analyze_memory_layout();

        if (!lock_queue.is_valid()) {
            throw std::runtime_error("LockBasedQueue validation failed");
        }

        auto result2 = EnhancedBenchmark::benchmark_queue_enhanced(
            lock_queue, "Lock-based Queue", iterations, num_threads, benchmark_runs);
        result2.print_statistics();
        benchmark_results.push_back(result2);

        // 3. False Sharing이 없는 Atomic 큐 테스트
        std::cout << "\n" << std::string(60, '=') << "\n";
        NoFalseSharingQueue no_sharing_queue;
        no_sharing_queue.analyze_memory_layout();

        if (!no_sharing_queue.is_valid()) {
            throw std::runtime_error("NoFalseSharingQueue validation failed");
        }

        auto result3 = EnhancedBenchmark::benchmark_queue_enhanced(
            no_sharing_queue, "Atomic Queue (No False Sharing)", iterations, num_threads, benchmark_runs);
        result3.print_statistics();
        benchmark_results.push_back(result3);

    } catch (const std::exception& e) {
        std::cerr << "\n오류 발생: " << e.what() << "\n";
        return;
    }

    // 결과 검증
    if (!ValidationFramework::validate_performance_results(benchmark_results)) {
        std::cout << "\n⚠️  성능 결과에 비정상적인 패턴이 감지되었습니다.\n";
    }

    // 4. 종합 결과 비교
    std::cout << "\n" << std::string(80, '=') << "\n";
    std::cout << "=== 동기화 방식별 성능 비교 ===\n";
    std::cout << std::fixed << std::setprecision(0);

    for (size_t i = 0; i < benchmark_results.size(); ++i) {
        const auto& result = benchmark_results[i];
        std::cout << (i + 1) << ". " << std::setw(30) << std::left << result.test_name
                  << ": " << std::setw(8) << std::right << static_cast<long>(result.mean_duration)
                  << " μs (±" << std::setw(6) << static_cast<long>(result.std_deviation) << ")\n";
    }

    // 성능 비교 분석
    if (benchmark_results.size() >= 3) {
        auto& atomic_sharing = benchmark_results[0];
        auto& lock_based = benchmark_results[1];
        auto& no_sharing = benchmark_results[2];

        double atomic_to_lock_ratio = lock_based.mean_duration / atomic_sharing.mean_duration;
        double atomic_to_optimized_ratio = atomic_sharing.mean_duration / no_sharing.mean_duration;
        double lock_to_optimized_ratio = lock_based.mean_duration / no_sharing.mean_duration;

        std::cout << "\n=== 성능 개선 비율 ===\n";
        std::cout << std::fixed << std::setprecision(2);
        std::cout << "Lock vs Atomic (False Sharing): " << atomic_to_lock_ratio << "배 ";
        if (atomic_to_lock_ratio > 1.0) {
            std::cout << "(Lock이 " << ((atomic_to_lock_ratio - 1.0) * 100) << "% 느림)\n";
        } else {
            std::cout << "(Lock이 " << ((1.0 - atomic_to_lock_ratio) * 100) << "% 빠름)\n";
        }

        std::cout << "Optimized vs Atomic (False Sharing): " << atomic_to_optimized_ratio << "배 ";
        if (atomic_to_optimized_ratio > 1.0) {
            std::cout << "(최적화로 " << ((atomic_to_optimized_ratio - 1.0) * 100) << "% 개선)\n";
        } else {
            std::cout << "(예상과 다른 결과 - CPU 아키텍처에 따라 다름)\n";
        }

        std::cout << "Optimized vs Lock: " << lock_to_optimized_ratio << "배 ";
        if (lock_to_optimized_ratio > 1.0) {
            std::cout << "(최적화가 " << ((lock_to_optimized_ratio - 1.0) * 100) << "% 빠름)\n";
        } else {
            std::cout << "(Lock이 더 빠름 - 낮은 경합에서 가능)\n";
        }
    }

    // 5. 메모리 사용량 비교
    std::cout << "\n=== 메모리 사용량 비교 ===\n";
    std::cout << "AtomicQueueStats:          " << std::setw(4) << sizeof(AtomicQueueStats) << " bytes\n";
    std::cout << "LockBasedQueueStats:       " << std::setw(4) << sizeof(LockBasedQueueStats) << " bytes\n";
    std::cout << "NoFalseSharingStats:       " << std::setw(4) << sizeof(NoFalseSharingStats) << " bytes\n";
    std::cout << "\n전체 객체 크기:\n";
    std::cout << "AtomicPacketQueue:         " << std::setw(4) << sizeof(AtomicPacketQueue) << " bytes\n";
    std::cout << "LockBasedQueue:            " << std::setw(4) << sizeof(LockBasedQueue) << " bytes\n";
    std::cout << "NoFalseSharingQueue:       " << std::setw(4) << sizeof(NoFalseSharingQueue) << " bytes\n";

    // 메모리 효율성 분석
    double memory_overhead_ratio = static_cast<double>(sizeof(NoFalseSharingStats)) / sizeof(AtomicQueueStats);
    std::cout << "\n메모리 오버헤드 비율: " << std::fixed << std::setprecision(1)
              << memory_overhead_ratio << "x ("
              << sizeof(NoFalseSharingStats) - sizeof(AtomicQueueStats)
              << " bytes 추가)\n";

    // 6. 발전된 권장사항 및 분석
    std::cout << "\n=== 동기화 방식 선택 가이드 ===\n";

    // 다이나믹한 권장사항 (결과에 기반)
    if (benchmark_results.size() >= 3) {
        auto& atomic_sharing = benchmark_results[0];
        auto& lock_based = benchmark_results[1];
        auto& no_sharing = benchmark_results[2];

        // 가장 빠른 방식 찾기
        auto fastest = std::min_element(benchmark_results.begin(), benchmark_results.end(),
            [](const BenchmarkResult& a, const BenchmarkResult& b) {
                return a.mean_duration < b.mean_duration;
            });

        std::cout << "🏆 최고 성능: " << fastest->test_name << "\n";

        if (fastest->test_name.find("No False Sharing") != std::string::npos) {
            std::cout << "   ✅ Cache-line aligned atomic operations이 최상의 성능\n";
            std::cout << "   ✅ 고성능 네트워크 애플리케이션에 권장\n";
            std::cout << "   ⚠️  메모리 오버헤드: " << memory_overhead_ratio << "x\n";
        } else if (fastest->test_name.find("Lock-based") != std::string::npos) {
            std::cout << "   ✅ Lock-based synchronization이 이 시스템에서 최적\n";
            std::cout << "   ✅ 낮은 경합 환경에서 효과적\n";
        } else {
            std::cout << "   ✅ Standard atomic operations이 균형잡힌 성능\n";
        }
    }

    // 상황별 권장사항
    std::cout << "\n=== 사용 시나리오별 권장사항 ===\n";

    std::cout << "📊 고성능 데이터 처리 (10M+ ops/sec):\n";
    std::cout << "   → NoFalseSharingQueue: 최대 성능, 메모리 여유 있을 때\n";
    std::cout << "   → AtomicPacketQueue: 균형잡힌 선택, 메모리 제약 있을 때\n";

    std::cout << "\n📈 일반적인 애플리케이션 (1M ops/sec 이하):\n";
    std::cout << "   → AtomicPacketQueue: 가장 균형잡힌 선택\n";
    std::cout << "   → LockBasedQueue: 단순한 구현 원할 때\n";

    std::cout << "\n🔒 복잡한 비즈니스 로직:\n";
    std::cout << "   → LockBasedQueue: 원자적 업데이트, 트랜잭션 지원\n";

    std::cout << "\n💾 리소스 제약 환경:\n";
    std::cout << "   → AtomicPacketQueue: 메모리 효율성 우선\n";
    std::cout << "   → LockBasedQueue: CPU 사용량 최소화\n";

    // 성능 특성 요약
    std::cout << "\n=== 성능 특성 요약 ===\n";
    for (const auto& result : benchmark_results) {
        std::cout << "\n" << result.test_name << ":\n";
        std::cout << "  - 평균 성능: " << std::fixed << std::setprecision(0)
                  << result.ops_per_second << " ops/sec\n";
        std::cout << "  - 안정성: " << std::fixed << std::setprecision(1)
                  << (result.std_deviation / result.mean_duration * 100) << "% 변동\n";
        std::cout << "  - 메모리: ";

        if (result.test_name.find("No False Sharing") != std::string::npos) {
            std::cout << sizeof(NoFalseSharingQueue) << " bytes (고메모리)";
        } else if (result.test_name.find("Lock-based") != std::string::npos) {
            std::cout << sizeof(LockBasedQueue) << " bytes (저메모리)";
        } else {
            std::cout << sizeof(AtomicPacketQueue) << " bytes (중간)";
        }
        std::cout << "\n";
    }

    // 최종 결론
    std::cout << "\n" << std::string(80, '=') << "\n";
    std::cout << "=== 최종 결론 ===\n";
    std::cout << "ℹ️  False Sharing은 멀티코어 시스템에서 심각한 성능 저하를 일으킬 수 있습니다.\n";
    std::cout << "✅ 적절한 메모리 정렬과 캐시 라인 최적화를 통해 크게 개선할 수 있습니다.\n";
    std::cout << "🚀 고성능 애플리케이션에서는 메모리 오버헤드를 감수하더라도 최적화가 필수입니다.\n";
    std::cout << "⚖️  성능과 메모리 사용량 간의 균형을 고려하여 선택하세요.\n";
}

/**
 * @brief False Sharing 분석 도구
 *
 * 이 프로그램은 세 가지 다른 동기화 전략을 비교하여 False Sharing의 영향을 시연합니다:
 *
 * 1. AtomicPacketQueue: False Sharing이 있는 일반적인 atomic 구조
 * 2. LockBasedQueue: 뮤텍스 기반 동기화
 * 3. NoFalseSharingQueue: 캐시 라인 정렬이 적용된 최적화 전략
 *
 * @author False Sharing Analysis Tool
 * @version 2.0 (Enhanced)
 * @date 2024
 *
 * 개선 사항:
 * - 동적 캐시 라인 크기 감지
 * - CPU 친화성 설정으로 정확한 측정
 * - 다중 실행 및 통계 분석
 * - 강화된 예외 처리
 * - 자동 검증 메커니즘
 * - 상세한 성능 분석 및 권장사항
 */
int main() {
    std::cout << "🚀 False Sharing 분석 도구 v2.0 (Enhanced Edition)\n";
    std::cout << std::string(60, '=') << "\n";
    std::cout << "이 도구는 다양한 동기화 전략의 성능을 비교하여\n";
    std::cout << "False Sharing 현상과 그 해결법을 실증적으로 분석합니다.\n\n";

    try {
        // 주요 분석 실행
        run_complete_analysis();

        std::cout << "\n\n" << std::string(60, '=') << "\n";
        std::cout << "✅ 분석 완료! 결과를 참고하여 애플리케이션에 적합한 동기화 전략을 선택하세요.\n";
        std::cout << "📄 추가 정보: make help 또는 README.md 참조\n";

    } catch (const std::runtime_error& e) {
        std::cerr << "\n❌ 런타임 오류: " << e.what() << "\n";
        std::cerr << "해결 방법:\n";
        std::cerr << "  1. 시스템 리소스 확인 (CPU, 메모리)\n";
        std::cerr << "  2. 권한 설정 확인 (CPU affinity 설정)\n";
        std::cerr << "  3. 컴파일러 버전 확인 (C++17 지원 필요)\n";
        return 2;
    } catch (const std::exception& e) {
        std::cerr << "\n❌ 예외 발생: " << e.what() << "\n";
        std::cerr << "디버그 정보를 위해 'make debug && make run-debug'를 실행하세요.\n";
        return 1;
    } catch (...) {
        std::cerr << "\n❌ 알 수 없는 오류가 발생했습니다.\n";
        std::cerr << "시스템 로그를 확인하거나 개발자에게 문의하세요.\n";
        return -1;
    }

    return 0;
}