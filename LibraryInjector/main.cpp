// Based on this gist by Saagar Jha:
// https://gist.github.com/saagarjha/a70d44951cb72f82efee3317d80ac07f

#include <vector>
#include <iostream>
#include <filesystem>

#include <EndpointSecurity/EndpointSecurity.h>
#include <bsm/libbsm.h>
#include <mach/mach.h>
#include <dispatch/dispatch.h>
#include <mach-o/loader.h>

#ifdef __arm64__
#include <mach/arm/thread_state.h>
#define x_thread_state_get_sp(state) (arm_thread_state64_get_sp(state))
#define X_THREAD_STATE ARM_THREAD_STATE64
typedef arm_thread_state64_t x_thread_state_t;
#elif __x86_64__
#include <mach/i386/thread_state.h>
#define x_thread_state_get_sp(state) (state.__rsp)
#define X_THREAD_STATE x86_THREAD_STATE64
typedef x86_thread_state64_t x_thread_state_t;
#else
#error "Only arm64 and x86_64 are currently supported"
#endif

namespace fs = std::filesystem;

static inline void _ensure(bool cond, const char *cond_s, const char *file, long line, const char *fn) {
    if (!(cond)) {
        throw std::runtime_error(std::string("") + "Check \"" + cond_s + "\" failed at " +
                                 file + ":" + std::to_string(line) + " in function " + fn);
    }
}
#define ensure(condition) (_ensure(condition, #condition, __FILE__, __LINE__, __FUNCTION__))

template <typename T, typename U>
static inline void _ensureEq(const T &a, const U &b,
                             const char *a_s, const char *b_s,
                             const char *file, long line, const char *fn) {
    if (a != b) {
        throw std::runtime_error(std::string("") + "Check \"" + a_s + " == " + b_s + "\" failed at " +
                                 file + ":" + std::to_string(line) + " in function " + fn + " (got " +
                                 std::to_string(a) + " != " + std::to_string(b) + ")");
    }
}
#define ensureEq(a, b) (_ensureEq(a, b, #a, #b, __FILE__, __LINE__, __FUNCTION__))

#define kcheck(a) (ensureEq(a, KERN_SUCCESS))

template <uint64_t alignment, typename T>
static constexpr inline T align(T orig) {
    static_assert(alignment <= (1 << sizeof(T)), "alignment too large for given type");
    static_assert(alignment && ((alignment & (alignment - 1)) == 0),
                  "alignment must be a positive power of two");
    return (orig + (T)alignment - 1) & ~((T)alignment - 1);
}
// static_assert(align<8>(15) == 16);
// static_assert(align<8>(16) == 16);
// static_assert(align<8>(17) == 24);

class TaskCursor {
private:
    const task_t task_;
    std::uintptr_t address_;
public:
    TaskCursor(task_t task, std::uintptr_t address) : task_(task), address_(address) {}

    const task_t &task() { return task_; }
    std::uintptr_t &address() { return address_; }

    void write(const void *val, unsigned int val_size) {
        vm_region_basic_info_data_64_t info;
        mach_msg_type_number_t info_sz = sizeof(info);
        vm_address_t region_addr = address_ / PAGE_SIZE * PAGE_SIZE;
        vm_size_t region_size;
        mach_port_t object; // unused
        kcheck(vm_region_64(task_, &region_addr, &region_size, VM_REGION_BASIC_INFO_64, reinterpret_cast<vm_region_info_64_t>(&info), &info_sz, &object));
        kcheck(vm_protect(task_, region_addr, region_size, false, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY));
        kcheck(vm_write(task_, address_, reinterpret_cast<vm_offset_t>(val), val_size));
        kcheck(vm_protect(task_, region_addr, region_size, false, info.protection));
        address_ += val_size;
    }

    template <typename T>
    void write(const T &val) {
        write(&val, sizeof(val));
    }

    void peek(void *out, size_t size) {
        size_t count;
        kcheck(vm_read_overwrite(task_, address_, size, reinterpret_cast<vm_address_t>(out), &count));
        ensureEq(count, size);
    }

    std::unique_ptr<char[]> peek(size_t size) {
        auto ptr = std::make_unique<char[]>(size);
        peek(ptr.get(), size);
        return ptr;
    }

    void scan(void *out, size_t size) {
        peek(out, size);
        address_ += size;
    }

    std::unique_ptr<char[]> scan(size_t size) {
        auto ptr = peek(size);
        address_ += size;
        return ptr;
    }

    template <typename T>
    T peek() {
        T t;
        peek(&t, sizeof(t));
        return t;
    }

    template <typename T>
    T scan() {
        T t;
        scan(&t, sizeof(t));
        return t;
    }

    std::vector<std::uintptr_t> scan_string_array() {
        std::vector<std::uintptr_t> strings;
        std::uintptr_t string;
        while ((string = scan<std::uintptr_t>())) {
            strings.push_back(string);
        }
        return strings;
    }

    std::string scan_string() {
        std::string string;
        char c;
        while ((c = scan<char>())) {
            string.push_back(c);
        }
        return string;
    }
};

// the cursor should point to the desired image header
static void insert_dylib(TaskCursor &cur, const std::string &library) {
    auto base = cur.address();
    auto mh = cur.scan<mach_header_64>();
    cur.address() += mh.sizeofcmds;

    auto cmdsize = (uint32_t)align<8>(sizeof(dylib_command) + library.length() + 1);
    std::unique_ptr mem = cur.peek(cmdsize);

    bool has_space = true;
    // TODO: Make this check smarter; the memory might be zeroed but still used somewhere (i.e. not just padding)
    for (unsigned i = 0; i < cmdsize; i++) {
        if (mem[i] != 0) {
            has_space = false;
            break;
        }
    }

    if (!has_space) {
        // use alternate mechanism, such as overwriting an existing LC?
        ensure(false && "not enough space");
    }

    dylib_command cmd = {
        .cmd = LC_LOAD_DYLIB,
        .cmdsize = cmdsize,
        .dylib = {
            .name = {
                .offset = sizeof(dylib_command)
            }
        }
    };
    memcpy(mem.get(), &cmd, sizeof(cmd));
    memcpy(mem.get() + sizeof(cmd), library.c_str(), library.length());
    cur.write(mem.get(), cmdsize);

    mh.sizeofcmds += cmdsize;
    mh.ncmds += 1;

    cur.address() = base;
    cur.write(mh);

    std::cout << "Injected!" << std::endl;
}

static void inject(pid_t pid, const std::string &library) {
    std::cout << "Injecting " << library << " into pid " << pid << std::endl;
    task_port_t task;
    kcheck(task_for_pid(mach_task_self(), pid, &task));

    thread_act_array_t threads;
    mach_msg_type_number_t count;
    kcheck(task_threads(task, &threads, &count));
    ensureEq(count, 1);

    x_thread_state_t state;
    count = sizeof(state);
    kcheck(thread_get_state(*threads, X_THREAD_STATE, reinterpret_cast<thread_state_t>(&state), &count));

    // the image load address is on top of the stack
    std::uintptr_t sp = x_thread_state_get_sp(state);
    auto cur = TaskCursor(task, sp);
    auto loadAddress = cur.scan<std::uintptr_t>();
    std::cout << "Found load address: " << reinterpret_cast<void *>(loadAddress) << std::endl;
    cur.address() = loadAddress;
    insert_dylib(cur, library);
}

int main(int argc, char **argv) {
    if (argc != 3) {
        std::cerr << "Usage: " << argv[0] << " <process path> <library to inject>" << std::endl;
        std::exit(1);
    }

    if (geteuid() != 0) {
        std::cerr << "You must run this program as root." << std::endl;
        std::exit(1);
    }

    fs::path process = argv[1];
    fs::path library = fs::canonical(argv[2]);

    es_client_t *client = NULL;
    ensureEq(es_new_client(&client, ^(es_client_t *client, const es_message_t *message) {
        switch (message->event_type) {
            case ES_EVENT_TYPE_AUTH_EXEC: {
                const char *name = message->event.exec.target->executable->path.data;
                if (fs::equivalent(name, process)) {
                    pid_t pid = audit_token_to_pid(message->process->audit_token);
                    inject(pid, library);
                }
                es_respond_auth_result(client, message, ES_AUTH_RESULT_ALLOW, false);
                break;
            }
            default:
                ensure(false && "Unexpected event type!");
        }
    }), ES_NEW_CLIENT_RESULT_SUCCESS);
    es_event_type_t events[] = { ES_EVENT_TYPE_AUTH_EXEC };
    ensureEq(es_subscribe(client, events, sizeof(events) / sizeof(*events)), ES_RETURN_SUCCESS);
    std::cout << "Listening..." << std::endl;
    dispatch_main();
}
