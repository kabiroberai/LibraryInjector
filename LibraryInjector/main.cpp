// Based on this gist by Saagar Jha:
// https://gist.github.com/saagarjha/a70d44951cb72f82efee3317d80ac07f

// Note: as of now, the library to be injected must re-export libSystem.B.dylib.
// this requirement should eventually be removed.

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

template <typename T>
static inline void _ensureEq(const T &a, const T &b,
                             const char *a_s, const char *b_s,
                             const char *file, long line, const char *fn) {
    if (a != b) {
        throw std::runtime_error(std::string("") + "Check \"" + a_s + " == " + b_s + "\" failed at " +
                                 file + ":" + std::to_string(line) + " in function " + fn + " (got " +
                                 std::to_string(a) + " != " + std::to_string(b) + ")");
    }
}
#define ensureEq(a, b) (_ensureEq(a, b, #a, #b, __FILE__, __LINE__, __FUNCTION__))

class TaskCursor {
private:
    task_t task_;
    std::uintptr_t address_;
public:
    TaskCursor(task_t task, std::uintptr_t address) : task_(task), address_(address) {}

    std::uintptr_t address() {
        return address_;
    }

    void set_address(std::uintptr_t address) {
        address_ = address;
    }

    void write(const void *val, unsigned int val_size) {
        vm_region_basic_info_data_64_t info;
        mach_msg_type_number_t info_sz = sizeof(info);
        vm_address_t region_addr = address_ / PAGE_SIZE * PAGE_SIZE;
        vm_size_t region_size;
        mach_port_t object; // unused
        ensureEq(vm_region_64(task_, &region_addr, &region_size, VM_REGION_BASIC_INFO_64, (vm_region_info_t)&info, &info_sz, &object), KERN_SUCCESS);
        ensureEq(vm_protect(task_, region_addr, region_size, false, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY), KERN_SUCCESS);
        ensureEq(vm_write(task_, address_, reinterpret_cast<vm_offset_t>(val), val_size), KERN_SUCCESS);
        ensureEq(vm_protect(task_, region_addr, region_size, false, info.protection), KERN_SUCCESS);
        address_ += val_size;
    }

    template <typename T>
    void write(const T &val) {
        write(&val, sizeof(val));
    }

    template <typename T>
    T peek() {
        T t;
        vm_size_t count;
        ensureEq(vm_read_overwrite(task_, address_, sizeof(t), reinterpret_cast<pointer_t>(&t), &count), KERN_SUCCESS);
        ensureEq(count, sizeof(t));
        return t;
    }

    template <typename T>
    T scan() {
        T ret = peek<T>();
        address_ += sizeof(T);
        return ret;
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

static const char tramp_name[] = "/tmp/tramp.dylib";

// the cursor should point to the desired image header
static void insert_dylib(TaskCursor &cur, const std::string &library) {
    auto base = cur.scan<mach_header_64>();
    auto ncmds = base.ncmds;
    for (unsigned i = 0; i < ncmds; i++) {
        uintptr_t hdr_loc = cur.address();
        auto hdr = cur.peek<load_command>();

        switch (hdr.cmd) {
            case LC_LOAD_DYLIB:
            case LC_REEXPORT_DYLIB:
            case LC_LOAD_WEAK_DYLIB:
            case LC_LOAD_UPWARD_DYLIB:
            case LC_LAZY_LOAD_DYLIB: {
                auto load_dylib = cur.peek<dylib_command>();
                const auto name_addr = hdr_loc + load_dylib.dylib.name.offset;
                cur.set_address(name_addr);
                auto name = cur.scan_string();
                if (name == "/usr/lib/libSystem.B.dylib") {
                    std::cout << "Found libSystem string at " << reinterpret_cast<void *>(name_addr) << std::endl;
                    cur.set_address(name_addr);
                    cur.write(tramp_name);
                    std::cout << "Patched!" << std::endl;
                    return;
                }
                break;
            }
            default:
                break;
        }

        cur.set_address(hdr_loc + hdr.cmdsize);
    }
}

static void inject(pid_t pid, const std::string &library) {
    std::cout << "Injecting " << library << " into pid " << pid << std::endl;
    task_port_t task;
    ensureEq(task_for_pid(mach_task_self(), pid, &task), KERN_SUCCESS);

    thread_act_array_t threads;
    mach_msg_type_number_t count;
    ensureEq(task_threads(task, &threads, &count), KERN_SUCCESS);
    ensureEq(count, (mach_msg_type_number_t)1);

    x_thread_state_t state;
    count = sizeof(state);
    ensureEq(thread_get_state(*threads, X_THREAD_STATE, reinterpret_cast<thread_state_t>(&state), &count), KERN_SUCCESS);

    // the image load address is on top of the stack
    std::uintptr_t sp = x_thread_state_get_sp(state);
    auto cur = TaskCursor(task, sp);
    auto loadAddress = cur.scan<std::uintptr_t>();
    std::cout << "Load address: " << reinterpret_cast<void *>(loadAddress) << std::endl;
    cur.set_address(loadAddress);
    insert_dylib(cur, library);
}

int main(int argc, char **argv) {
    if (argc != 3) {
        std::cerr << "Usage: " << *argv << " <process path> <library to inject>" << std::endl;
        std::exit(1);
    }

    if (getuid() != 0) {
        std::cerr << "You must run this program as root." << std::endl;
        std::exit(1);
    }

    char *process = argv[1];
    char *library = argv[2];

    if (fs::exists(tramp_name)) fs::remove(tramp_name);
    fs::copy(library, tramp_name);

    es_client_t *client = NULL;
    ensureEq(es_new_client(&client, ^(es_client_t *client, const es_message_t *message) {
        switch (message->event_type) {
            case ES_EVENT_TYPE_AUTH_EXEC: {
                const char *name = message->event.exec.target->executable->path.data;
                if (!std::strcmp(name, process)) {
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
