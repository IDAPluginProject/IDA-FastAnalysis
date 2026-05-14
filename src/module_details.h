#pragma once
#include <libhat.hpp>

#ifdef __linux__
#ifndef IDA_8
#define CONFIG_SWITCH(win_ida_9, win_ida_8, linux_ida_9) linux_ida_9
#endif
#elifdef WIN32
#ifdef IDA_8
#define CONFIG_SWITCH(win_ida_9, win_ida_8, linux_ida_9) win_ida_8
#else
#define CONFIG_SWITCH(win_ida_9, win_ida_8, linux_ida_9) win_ida_9
#endif
#endif

#ifndef CONFIG_SWITCH
#error Unsupported platform/configuration
#endif

inline static constexpr hat::cstring_view
    pc_mod_name = CONFIG_SWITCH("pc.dll", "pc64.dll", "pc.so"),
    ida_mod_name = CONFIG_SWITCH("ida.dll", "ida64.dll", "libida.so");

inline static constexpr hat::fixed_string
    metapc_hook_sig = CONFIG_SWITCH(
        "48 83 ec ? 48 8b 05 ? ? ? ? 48 33 c4 48 89 44 24 38 41 b8 02 00 00 00",
        "40 53 48 83 EC ? 48 8b 05 ? ? ? ? 48 33 C4 48 89 44 24 38",
        "00"); // Placeholder, function is inlined on linux because gcc is evil

// for 9.2 windows only
inline static constexpr hat::fixed_string
    arm_hook_sig = "48 83 ec ? 48 8b 05 ? ? ? ? 48 33 c4 48 89 44 24 38 48 8b d1 41 b8 02";

#ifdef __linux__
#define HOOK_XREFBLK
#endif

// linux, currently 9.2(+?) only: point to the instruction after calls to xrefblk_t_first_to in pc.so's handle_operand

inline static constexpr hat::fixed_string
    metapc_handle_op_ret_addr_1 = "84 c0 75 ? e9 ? ? ? ? 0f 1f 44 00";

inline static constexpr hat::fixed_string
    metapc_handle_op_ret_addr_2 = "84 c0 74 ? 66 0f 1f 84 00 ? ? ? ? 80 7c 24";

// arm stuff: same as above but found in libida.so reg_finder_emulate_mem_read

inline static constexpr hat::fixed_string
    arm_handle_op_ret_addr_1 = "eb ? 90 80 bc 24 ? ? ? ? ? 0f 84";

inline static constexpr hat::fixed_string
    arm_handle_op_ret_addr_2 = "eb ? 66 90 80 bc 24 ? ? ? ? ? 74";



#undef CONFIG_SWITCH