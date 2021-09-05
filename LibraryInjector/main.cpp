// Based on this gist by Saagar Jha:
// https://gist.github.com/saagarjha/a70d44951cb72f82efee3317d80ac07f

// You must run this program as root.

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

#define ensure(condition)                                                                                         \
	do {                                                                                                          \
		if (!(condition)) {                                                                                       \
			throw std::runtime_error(std::string("") + "Check \"" + #condition "\" failed at " +                  \
			                         __FILE__ + ":" + std::to_string(__LINE__) + " in function " + __FUNCTION__); \
		}                                                                                                         \
	} while (0)

template <typename T>
T scan(task_port_t task, std::uintptr_t &address) {
	T t;
	vm_size_t count;
	ensure(vm_read_overwrite(task, address, sizeof(t), reinterpret_cast<pointer_t>(&t), &count) == KERN_SUCCESS && count == sizeof(t));
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

std::uintptr_t rearrange_stack(task_port_t task, const std::string &library, std::uintptr_t sp) {
	auto loadAddress = scan<std::uintptr_t>(task, sp);
	auto argc = scan<std::uintptr_t>(task, sp);

	auto argvAddresses = read_string_array(task, sp);
	auto envpAddresses = read_string_array(task, sp);
	auto appleAddresses = read_string_array(task, sp);

	auto stringReader = [task](const std::uintptr_t address) {
		return read_string(task, address);
	};
	auto argv = std::vector<std::string>{};
	std::transform(argvAddresses.begin(), argvAddresses.end(), std::back_inserter(argv), stringReader);
	auto envp = std::vector<std::string>{};
	std::transform(envpAddresses.begin(), envpAddresses.end(), std::back_inserter(envp), stringReader);
	auto apple = std::vector<std::string>{};
	std::transform(appleAddresses.begin(), appleAddresses.end(), std::back_inserter(apple), stringReader);

	auto dyld_insert_libraries = std::find_if(envp.begin(), envp.end(), [](const auto &string) {
		return string.starts_with("DYLD_INSERT_LIBRARIES=");
	});
	if (dyld_insert_libraries != envp.end()) {
		*dyld_insert_libraries += ":" + library;
	} else {
		auto variable = "DYLD_INSERT_LIBRARIES=" + library;
		envp.push_back(variable);
	}

	argvAddresses.clear();
	envpAddresses.clear();
	appleAddresses.clear();

	auto strings = std::vector<char>{};

	auto arrayGenerator = [&strings](auto &addresses, const auto &string) {
		addresses.push_back(strings.size());
		std::copy(string.begin(), string.end(), std::back_inserter(strings));
		strings.push_back('\0');
	};
	std::for_each(argv.begin(), argv.end(), std::bind(arrayGenerator, std::ref(argvAddresses), std::placeholders::_1));
	std::for_each(envp.begin(), envp.end(), std::bind(arrayGenerator, std::ref(envpAddresses), std::placeholders::_1));
	std::for_each(apple.begin(), apple.end(), std::bind(arrayGenerator, std::ref(appleAddresses), std::placeholders::_1));

	sp -= strings.size();
	sp = sp / sizeof(std::uintptr_t) * sizeof(std::uintptr_t);
	ensure(vm_write(task, sp, reinterpret_cast<vm_offset_t>(strings.data()), strings.size()) == KERN_SUCCESS);

	auto rebaser = [sp](auto &&address) {
		address += sp;
	};
	std::for_each(argvAddresses.begin(), argvAddresses.end(), rebaser);
	std::for_each(envpAddresses.begin(), envpAddresses.end(), rebaser);
	std::for_each(appleAddresses.begin(), appleAddresses.end(), rebaser);

	auto addresses = std::vector<std::uintptr_t>{};
	std::copy(argvAddresses.begin(), argvAddresses.end(), std::back_inserter(addresses));
	addresses.push_back(0);
	std::copy(envpAddresses.begin(), envpAddresses.end(), std::back_inserter(addresses));
	addresses.push_back(0);
	std::copy(appleAddresses.begin(), appleAddresses.end(), std::back_inserter(addresses));
	addresses.push_back(0);

	sp -= addresses.size() * sizeof(std::uintptr_t);
	ensure(vm_write(task, sp, reinterpret_cast<vm_offset_t>(addresses.data()), addresses.size() * sizeof(std::uintptr_t)) == KERN_SUCCESS);
	sp -= sizeof(uintptr_t);
	ensure(vm_write(task, sp, reinterpret_cast<vm_offset_t>(&argc), sizeof(std::uintptr_t)) == KERN_SUCCESS);
	sp -= sizeof(uintptr_t);
	ensure(vm_write(task, sp, reinterpret_cast<vm_offset_t>(&loadAddress), sizeof(std::uintptr_t)) == KERN_SUCCESS);
	return sp;
}
__asm__(
    ".globl _patch_start\n"
    ".globl _patch_end\n"
    "_patch_start:\n"
#if __arm64__
    "\tret\n"
#elif __x86_64__
    "\tret\n"
#endif
    "_patch_end:\n");

extern char patch_start;
extern char patch_end;

void write_patch(task_t task, std::uintptr_t address) {
	ensure(vm_protect(task, address / PAGE_SIZE * PAGE_SIZE, PAGE_SIZE, false, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY) == KERN_SUCCESS);
	ensure(vm_write(task, address, reinterpret_cast<vm_offset_t>(&patch_start), &patch_end - &patch_start) == KERN_SUCCESS);
	ensure(vm_protect(task, address / PAGE_SIZE * PAGE_SIZE, PAGE_SIZE, false, VM_PROT_READ | VM_PROT_EXECUTE) == KERN_SUCCESS);
}

void patch_restrictions(task_t task, std::uintptr_t pc) {
	task_dyld_info_data_t dyldInfo;
	mach_msg_type_number_t count = TASK_DYLD_INFO_COUNT;
	ensure(task_info(mach_task_self(), TASK_DYLD_INFO, reinterpret_cast<task_info_t>(&dyldInfo), &count) == KERN_SUCCESS);
	auto all_image_infos = reinterpret_cast<dyld_all_image_infos *>(dyldInfo.all_image_info_addr);
	const auto header = reinterpret_cast<const mach_header_64 *>(all_image_infos->dyldImageLoadAddress);
	uintptr_t location = reinterpret_cast<uintptr_t>(header + 1);
	uintptr_t base = reinterpret_cast<uintptr_t>(header);
	for (unsigned i = 0; i < header->ncmds; ++i) {
		auto command = reinterpret_cast<load_command *>(location);
		if (command->cmd == LC_SYMTAB) {
			auto command = reinterpret_cast<symtab_command *>(location);
			auto symbols = std::span{reinterpret_cast<nlist_64 *>(base + command->symoff), command->nsyms};
			auto _dyld_start = std::find_if(symbols.begin(), symbols.end(), [base, command](const auto &symbol) {
				return !std::strcmp(reinterpret_cast<char *>(base + command->stroff) + symbol.n_un.n_strx, "__dyld_start");
			});
			auto pruneEnvVars = std::find_if(symbols.begin(), symbols.end(), [base, command](const auto &symbol) {
				return !std::strcmp(reinterpret_cast<char *>(base + command->stroff) + symbol.n_un.n_strx, "__ZN5dyld413ProcessConfig8Security12pruneEnvVarsERNS0_7ProcessE");
			});
			write_patch(task, pc + pruneEnvVars->n_value - _dyld_start->n_value);
			return;
		}
		location += command->cmdsize;
	}
	ensure(false);
}

void inject(pid_t pid, const std::string &library) {
	task_port_t task;
	ensure(task_for_pid(mach_task_self(), pid, &task) == KERN_SUCCESS);
	thread_act_array_t threads;
	mach_msg_type_number_t count;
	ensure(task_threads(task, &threads, &count) == KERN_SUCCESS);
	ensure(count == 1);
#if __arm64__
	arm_thread_state64_t state;
	count = ARM_THREAD_STATE64_COUNT;
	thread_state_flavor_t flavor = ARM_THREAD_STATE64;
#elif __x86_64__
	x86_thread_state64_t state;
	count = x86_THREAD_STATE64_COUNT;
	thread_state_flavor_t flavor = x86_THREAD_STATE64;
#endif
	ensure(thread_get_state(*threads, flavor, reinterpret_cast<thread_state_t>(&state), &count) == KERN_SUCCESS);

#if __arm64__
	ensure(thread_convert_thread_state(*threads, THREAD_CONVERT_THREAD_STATE_TO_SELF, flavor, reinterpret_cast<thread_state_t>(&state), count, reinterpret_cast<thread_state_t>(&state), &count) == KERN_SUCCESS);
	auto sp = rearrange_stack(task, library, arm_thread_state64_get_sp(state));
	arm_thread_state64_set_sp(state, sp);
	patch_restrictions(task, arm_thread_state64_get_pc(state));
	ensure(thread_convert_thread_state(*threads, THREAD_CONVERT_THREAD_STATE_FROM_SELF, flavor, reinterpret_cast<thread_state_t>(&state), count, reinterpret_cast<thread_state_t>(&state), &count) == KERN_SUCCESS);
#elif __x86_64__
	auto sp = rearrange_stack(task, library, static_cast<std::uintptr_t>(state.__rsp));
	state.__rsp = sp;
	patch_restrictions(task, state.__rip);
#endif
	ensure(thread_set_state(*threads, flavor, reinterpret_cast<thread_state_t>(&state), count) == KERN_SUCCESS);
}

int main(int argc, char **argv) {
	if (argc != 3) {
		std::cerr << "Usage: " << *argv << " <process path> <library to inject>" << std::endl;
		std::exit(1);
	}
	char *process = *++argv;
	char *library = *++argv;

	es_client_t *client = NULL;
	ensure(es_new_client(&client, ^(es_client_t *client, const es_message_t *message) {
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
	       }) == ES_NEW_CLIENT_RESULT_SUCCESS);
	es_event_type_t events[] = {ES_EVENT_TYPE_AUTH_EXEC};
	ensure(es_subscribe(client, events, sizeof(events) / sizeof(*events)) == ES_RETURN_SUCCESS);
	dispatch_main();
}
