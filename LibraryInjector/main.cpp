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
#define x_thread_state_set_sp(state, sp) (arm_thread_state64_set_sp(state, sp))
#define X_THREAD_STATE ARM_THREAD_STATE64
typedef arm_thread_state64_t x_thread_state_t;
#elif __x86_64__
#include <mach/i386/thread_state.h>
#define x_thread_state_get_sp(state) (state.__rsp)
#define x_thread_state_set_sp(state, sp) do { state.__rsp = sp; } while (0)
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

template <typename T, typename U>
static constexpr inline T round_down(T orig, U boundary) {
    return orig / boundary * boundary;
}
//static_assert(round_down(8, 7) == 7);
//static_assert(round_down(12, 7) == 7);
//static_assert(round_down(14, 7) == 14);

class TaskCursor {
private:
    const task_t task_;
    std::uintptr_t address_;
public:
    TaskCursor(task_t task, std::uintptr_t address) : task_(task), address_(address) {}

    const task_t &task() { return task_; }
    std::uintptr_t &address() { return address_; }

    // write next val_size bytes without moving cursor
    void write_ahead(const void *val, unsigned int val_size) const {
        vm_region_basic_info_data_64_t info;
        mach_msg_type_number_t info_sz = sizeof(info);
        vm_address_t region_addr = round_down(address_, PAGE_SIZE);
        vm_size_t region_size;
        mach_port_t object; // unused
        kcheck(vm_region_64(task_, &region_addr, &region_size, VM_REGION_BASIC_INFO_64, reinterpret_cast<vm_region_info_64_t>(&info), &info_sz, &object));
        kcheck(vm_protect(task_, region_addr, region_size, false, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY));
        kcheck(vm_write(task_, address_, reinterpret_cast<vm_offset_t>(val), val_size));
        kcheck(vm_protect(task_, region_addr, region_size, false, info.protection));
    }

    void write(const void *val, unsigned int val_size) {
        write_ahead(val, val_size);
        address_ += val_size;
    }

    template <typename T>
    void write_ahead(const T &val) const {
        write_ahead(&val, sizeof(val));
    }

    template <typename T>
    void write(const T &val) {
        write(&val, sizeof(val));
    }

    void peek(void *out, size_t size) const {
        size_t count;
        kcheck(vm_read_overwrite(task_, address_, size, reinterpret_cast<vm_address_t>(out), &count));
        ensureEq(count, size);
    }

    std::unique_ptr<char[]> peek(size_t size) const {
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
    T peek() const {
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

// Adds DYLD_INSERT_LIBRARIES= to stack envp, moves cursor to new stack base
// Returns load address.
//
// This function is needed because without DYLD_INSERT_LIBRARIES or some
// other dyld env var, dyld may use a cached launch closure and ignore
// our new load command. We're good as long as we have a relevant dyld
// env var, even if it's empty and/or ignored by dyld.
static std::uintptr_t rearrange_stack(TaskCursor &cur) {
    /// https://github.com/apple/darwin-xnu/blob/2ff845c2e033bd0ff64b5b6aa6063a1f8f65aa32/bsd/kern/kern_exec.c#L4919
    ///
    /// initial stack layout (with dummy addresses):
    /// ...
    /// 0xFFB8 <uninitialized>
    /// 0xFFC0 <uninitialized>
    /// --- _dyld_start frame vvv ---
    /// 0xFFC8 (cursor) load_address
    /// 0xFFD0 argc
    /// 0xFFD8 argv[]
    /// 0xFFE0 envp[]
    /// 0xFFE8 apple[]
    /// 0xFFF0 strings
    /// --- start of stack ---
    ///
    /// final stack layout (with dummy addresses, slightly simplified):
    /// ...
    /// 0xFFB8 <uninitialized>
    /// --- _dyld_start frame vvv ---
    /// 0xFFC0 (cursor) load_address
    /// 0xFFC8 argc
    /// 0xFFD0 argv[]     -|
    /// 0xFFD8 envp[]      | - rebased
    /// 0xFFE0 apple[]    -|
    /// 0xFFE8 strings
    /// 0xFFF0 "DYLD_INSERT_LIBRARIES="
    /// --- start of stack ---

    std::cout << "Rearranging... SP: " << (void *)cur.address() << std::endl;

    auto loadAddress = cur.scan<std::uintptr_t>();
    auto argc = cur.scan<std::uintptr_t>();
    auto argvAddresses = cur.scan_string_array();
    auto envpAddresses = cur.scan_string_array();
    auto appleAddresses = cur.scan_string_array();

    // cursor is now at the strings

    auto stringReader = [&](const std::uintptr_t address) {
        auto oldAddr = cur.address();
        cur.address() = address;
        auto str = cur.scan_string();
        cur.address() = oldAddr;
        return str;
    };
    std::vector<std::string> argv;
    std::transform(argvAddresses.begin(), argvAddresses.end(), std::back_inserter(argv), stringReader);
    std::vector<std::string> envp;
    std::transform(envpAddresses.begin(), envpAddresses.end(), std::back_inserter(envp), stringReader);
    std::vector<std::string> apple;
    std::transform(appleAddresses.begin(), appleAddresses.end(), std::back_inserter(apple), stringReader);

    auto dyld_insert_libraries = std::find_if(envp.begin(), envp.end(), [&](const auto &string) {
        return string.starts_with("DYLD_INSERT_LIBRARIES=");
    });
    // if envp already has a DYLD_INSERT_LIBRARIES, no need to do anything
    if (dyld_insert_libraries == envp.end()) {
        // we don't actually insert the library this way; we just need
        // to ensure this env var exists so that dyld discards its
        // closure.
        envp.push_back("DYLD_INSERT_LIBRARIES=");
    }

    argvAddresses.clear();
    envpAddresses.clear();
    appleAddresses.clear();

    std::vector<char> strings;

    auto arrayGenerator = [&](auto &addresses, const auto &string) {
        addresses.push_back(strings.size());
        std::copy(string.begin(), string.end(), std::back_inserter(strings));
        strings.push_back('\0');
    };
    std::for_each(argv.begin(), argv.end(), std::bind(arrayGenerator, std::ref(argvAddresses), std::placeholders::_1));
    std::for_each(envp.begin(), envp.end(), std::bind(arrayGenerator, std::ref(envpAddresses), std::placeholders::_1));
    std::for_each(apple.begin(), apple.end(), std::bind(arrayGenerator, std::ref(appleAddresses), std::placeholders::_1));

    // it's okay if this overwrites the arguments on the stack since we've saved them
    // locally, and intend to write rebased versions onto the stack later
    cur.address() = round_down(cur.address() - strings.size(), sizeof(std::uintptr_t));
    cur.write_ahead(strings.data(), (unsigned int)strings.size());

    auto rebaser = [&](auto &&address) {
        address += cur.address();
    };
    std::for_each(argvAddresses.begin(), argvAddresses.end(), rebaser);
    std::for_each(envpAddresses.begin(), envpAddresses.end(), rebaser);
    std::for_each(appleAddresses.begin(), appleAddresses.end(), rebaser);

    std::vector<std::uintptr_t> addresses;
    addresses.reserve(argvAddresses.size() + 1 + envpAddresses.size() + 1 + appleAddresses.size() + 1);
    std::copy(argvAddresses.begin(), argvAddresses.end(), std::back_inserter(addresses));
    addresses.push_back(0);
    std::copy(envpAddresses.begin(), envpAddresses.end(), std::back_inserter(addresses));
    addresses.push_back(0);
    std::copy(appleAddresses.begin(), appleAddresses.end(), std::back_inserter(addresses));
    addresses.push_back(0);

    const auto stackTop = cur.address() - (addresses.size() + 2) * sizeof(std::uintptr_t);
    cur.address() = stackTop;
    cur.write(loadAddress);
    cur.write(argc);
    cur.write(addresses.data(), (unsigned int)addresses.size() * sizeof(std::uintptr_t));
    cur.address() = stackTop;

    std::cout << "Rearranged! SP: " << (void *)stackTop << std::endl;

    return loadAddress;
}

// the cursor should point to the desired image header
static void insert_dylib(TaskCursor &cur, const std::string &library) {
    const auto base = cur.address();

    std::cout << "Inserting... MH: " << (void *)base << std::endl;

    auto mh = cur.scan<mach_header_64>();
    cur.address() += mh.sizeofcmds;

    // +1 to NUL-terminate library
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

    std::cout << "Inserted!" << std::endl;
}

static void inject(pid_t pid, const std::string &library) {
    std::string libname = fs::path(library).filename().string();
    std::cout << "Injecting " << libname << " into pid " << pid << std::endl;

    task_port_t task;
    kcheck(task_for_pid(mach_task_self(), pid, &task));

    thread_act_array_t threads;
    mach_msg_type_number_t count;
    kcheck(task_threads(task, &threads, &count));
    ensureEq(count, 1);

    x_thread_state_t state;
    count = sizeof(state);
    kcheck(thread_get_state(threads[0], X_THREAD_STATE, reinterpret_cast<thread_state_t>(&state), &count));
    kcheck(thread_convert_thread_state(threads[0], THREAD_CONVERT_THREAD_STATE_TO_SELF, X_THREAD_STATE, reinterpret_cast<thread_state_t>(&state), count, reinterpret_cast<thread_state_t>(&state), &count));

    auto cur = TaskCursor(task, x_thread_state_get_sp(state));
    const auto load_addr = rearrange_stack(cur);
    x_thread_state_set_sp(state, cur.address());
    cur.address() = load_addr;

    kcheck(thread_convert_thread_state(*threads, THREAD_CONVERT_THREAD_STATE_FROM_SELF, X_THREAD_STATE, reinterpret_cast<thread_state_t>(&state), count, reinterpret_cast<thread_state_t>(&state), &count));
    kcheck(thread_set_state(*threads, X_THREAD_STATE, reinterpret_cast<thread_state_t>(&state), count));

    insert_dylib(cur, library);

    std::cout << "Injected " << libname << "!" << std::endl;
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
                    try {
                        inject(pid, library);
                    } catch (const std::exception &e) {
                        std::cerr << "error: Failed to inject: " << e.what() << std::endl;
                    }
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
