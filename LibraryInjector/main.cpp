// Based on this gist by Saagar Jha:
// https://gist.github.com/saagarjha/a70d44951cb72f82efee3317d80ac07f

// Note: as of now, the library to be injected must re-export libSystem.B.dylib.
// this requirement should eventually be removed.

#include <EndpointSecurity/EndpointSecurity.h>
#include <algorithm>
#include <bsm/libbsm.h>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <dispatch/dispatch.h>
#include <functional>
#include <iostream>
#include <mach-o/dyld_images.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#ifdef __arm64__
#include <mach/arm/thread_state.h>
#elif __x86_64__
#include <mach/i386/thread_state.h>
#else
#error "Only arm64 and x86_64 are currently supported"
#endif
#include <mach/mach.h>
#include <ptrauth.h>
#include <span>
#include <stdexcept>
#include <string>
#include <vector>
#include <filesystem>

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

void write_val(task_t task, std::uintptr_t address, const void *val, unsigned int valsize) {
    vm_region_basic_info_data_64_t info;
    mach_msg_type_number_t infoCnt = sizeof(info);
    vm_address_t region_addr = address / PAGE_SIZE * PAGE_SIZE;
    vm_size_t region_size;
    mach_port_t object; // unused
    ensureEq(vm_region_64(task, &region_addr, &region_size, VM_REGION_BASIC_INFO_64, (vm_region_info_t)&info, &infoCnt, &object), KERN_SUCCESS);
    ensureEq(vm_protect(task, region_addr, region_size, false, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY), KERN_SUCCESS);
    ensureEq(vm_write(task, address, reinterpret_cast<vm_offset_t>(val), valsize), KERN_SUCCESS);
    ensureEq(vm_protect(task, region_addr, region_size, false, info.protection), KERN_SUCCESS);
}

template <typename T>
void write_val(task_t task, std::uintptr_t address, const T &val) {
    write_val(task, address, &val, sizeof(T));
}

template <typename T>
T scan(task_port_t task, std::uintptr_t &address) {
    T t;
    vm_size_t count;
    ensureEq(vm_read_overwrite(task, address, sizeof(t), reinterpret_cast<pointer_t>(&t), &count), KERN_SUCCESS);
    ensureEq(count, sizeof(t));
    address += sizeof(t);
    return t;
}

std::vector<std::uintptr_t> read_string_array(task_port_t task, std::uintptr_t &base) {
    auto strings = std::vector<std::uintptr_t>{};
    std::uintptr_t string;
    do {
        string = scan<std::uintptr_t>(task, base);
        strings.push_back(string);
    } while (string);
    strings.pop_back();
    return strings;
}

std::string read_string(task_port_t task, std::uintptr_t address) {
    auto string = std::string{};
    char c;
    do {
        c = scan<char>(task, address);
        string.push_back(c);
    } while (c);
    string.pop_back();
    return string;
}

#if __arm64__
#define thread_state_get_sp(state) (arm_thread_state64_get_sp(state))
#elif __x86_64__
#define thread_state_get_sp(state) (state.__rsp)
#endif

static const char tramp_name[] = "/tmp/tramp.dylib";

static void insert_dylib(task_port_t task, uintptr_t baseptr, const std::string &library) {
    uintptr_t loc = baseptr;
    auto base = scan<mach_header_64>(task, loc);
    auto ncmds = base.ncmds;
    for (unsigned i = 0; i < ncmds; i++) {
        uintptr_t hdr_loc = loc;
        auto hdr = scan<load_command>(task, hdr_loc);
        hdr_loc = loc;

        switch (hdr.cmd) {
            case LC_LOAD_DYLIB:
            case LC_REEXPORT_DYLIB:
            case LC_LOAD_WEAK_DYLIB:
            case LC_LOAD_UPWARD_DYLIB:
            case LC_LAZY_LOAD_DYLIB:
                auto load_dylib = scan<dylib_command>(task, hdr_loc);
                auto name_addr = loc + load_dylib.dylib.name.offset;
                auto name = read_string(task, name_addr);
                if (name == "/usr/lib/libSystem.B.dylib") {
                    std::cout << "Found libSystem string at " << reinterpret_cast<void *>(name_addr) << std::endl;
                    write_val(task, name_addr, tramp_name);
                    std::cout << "Patched!" << std::endl;
                    return;
                }
                break;
        }

        loc += hdr.cmdsize;
    }
}

void inject(pid_t pid, const std::string &library) {
    std::cout << "Injecting " << library << " into pid " << pid << std::endl;
    task_port_t task;
    ensureEq(task_for_pid(mach_task_self(), pid, &task), KERN_SUCCESS);

    thread_act_array_t threads;
    mach_msg_type_number_t count;
    ensureEq(task_threads(task, &threads, &count), KERN_SUCCESS);
    ensureEq(count, (mach_msg_type_number_t)1);
#if __arm64__
    arm_thread_state64_t state;
    count = ARM_THREAD_STATE64_COUNT;
    thread_state_flavor_t flavor = ARM_THREAD_STATE64;
#elif __x86_64__
    x86_thread_state64_t state;
    count = x86_THREAD_STATE64_COUNT;
    thread_state_flavor_t flavor = x86_THREAD_STATE64;
#endif
    ensureEq(thread_get_state(*threads, flavor, reinterpret_cast<thread_state_t>(&state), &count), KERN_SUCCESS);

    // the image load address is on top of the stack
    std::uintptr_t sp = thread_state_get_sp(state);
    auto loadAddress = scan<std::uintptr_t>(task, sp);
    std::cout << "Load address: " << reinterpret_cast<void *>(loadAddress) << std::endl;
    insert_dylib(task, loadAddress, library);
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

    char *process = *++argv;
    char *library = *++argv;

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
    es_event_type_t events[] = {ES_EVENT_TYPE_AUTH_EXEC};
    ensureEq(es_subscribe(client, events, sizeof(events) / sizeof(*events)), ES_RETURN_SUCCESS);
    std::cout << "Listening..." << std::endl;
    dispatch_main();
}
