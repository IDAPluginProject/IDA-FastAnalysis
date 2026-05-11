#include <chrono>
#include <filesystem>
#include <future>
#include <safetyhook.hpp>
#include <unordered_set>
#include <libhat.hpp>

#include "ref_scanner.h"

#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <diskio.hpp>

// platform and IDA version-specific info, includes sigs
#include "module_details.h"

// IDA's closed source processor for x86_64
struct pc_t : procmod_t {};

struct FastAnalysisPlugin final : plugmod_t {
    inline static FastAnalysisPlugin* SINGLETON{};

    FastAnalysisPlugin() {
        bool is_arm = false;
        auto proc_name = inf_get_procname();

        if (proc_name == "metapc") {
            auto pc_path = get_proc_file_path(pc_mod_name);

            if (!pc_path.empty())
                m_proc_mod = hat::process::get_module(pc_path);

            if (!m_proc_mod) {
                msg("FastAnalysis failed to initialize: couldn't load proc module\n");
                return;
            }
        } else if (proc_name == "ARM") {
            // the function we need to hook for ARM is just in ida.dll, weirdly enough
            is_arm = true;
        } else {
            msg("FastAnalysis is not supported for this target: %s\n", proc_name.c_str());
            return;
        }

        m_ida_mod = hat::process::get_module(ida_mod_name);

        if (!m_ida_mod || !extract_executable_section(*m_ida_mod, m_ida_mod_text_section)) {
            msg("FastAnalysis failed to initialize: couldn't load main ida module\n");
            return;
        }

        if (m_proc_mod && !extract_executable_section(*m_proc_mod, m_proc_mod_text_section)) {
            msg("FastAnalysis failed to initialize: couldn't load proc module\n");
            return;
        }

        bool result;
        if (is_arm)
            result = init_arm();
        else
            result = init_metapc();

        if (result)
            m_active = true;
    }

    ~FastAnalysisPlugin() override = default;

    bool run(size_t arg) override {
        // TODO: settings menu

        if (m_active)
            info("FastAnalysis is active\n");
        else
            info("FastAnalysis is not active\n");

        return true;
    }

    static std::string get_proc_file_path(hat::cstring_view filename) {
        char path[QMAXPATH] = {};

        if (getsysfile(path, sizeof(path), filename.c_str(), "procs"))
            return path;

        return "";
    }

    // get largest executable section
    static bool extract_executable_section(const hat::process::module& mod, std::span<std::byte>& span) {
        size_t last_section_size = 0;

        mod.for_each_segment([&](std::span<std::byte> section, hat::protection protection) {
           if (static_cast<bool>(protection & hat::protection::Execute)) {
                if (section.size() > last_section_size) {
                    span = section;
                    last_section_size = section.size();
                }
           }

            return true;
        });

        return last_section_size > 0;
    }

    bool init_arm() {
#ifdef HOOK_XREFBLK
        m_handle_operand_ret_addrs[0] = hat::find_pattern(m_ida_mod_text_section,
            hat::compile_signature<arm_handle_op_ret_addr_1>()).get();

        m_handle_operand_ret_addrs[1] = hat::find_pattern(m_ida_mod_text_section,
            hat::compile_signature<arm_handle_op_ret_addr_2>()).get();

        if (std::ranges::contains(m_handle_operand_ret_addrs, nullptr)) {
            warning("FastAnalysis may not support this IDA version (signature dead)");
            return false;
        }

        m_xrefblk_hook = safetyhook::create_inline(xrefblk_t_first_to, xrefblk_t_first_to_hook);
        auto enable_result = m_xrefblk_hook.enable();
#else
        auto pattern = hat::compile_signature<arm_hook_sig>();

        hat::scan_result result = hat::find_pattern(m_ida_mod_text_section, pattern,
            hat::scan_alignment::X16, hat::scan_hint::x86_64);

        if (!result.has_result()) {
            warning("FastAnalysis may not support this IDA version (signature result not found)\n");
            return false;
        }

        m_arm_has_write_dref_hook = safetyhook::create_inline(result.get(), arm_has_write_dref_hook);


        auto enable_result = m_arm_has_write_dref_hook.enable();
#endif
        if (!enable_result.has_value()) {
            warning("Failed to enable hook, FastAnalysis will not function");
            return false;
        }

        return true;
    }

    bool init_metapc() {
#ifdef HOOK_XREFBLK
        m_handle_operand_ret_addrs[0] = hat::find_pattern(m_proc_mod_text_section,
            hat::compile_signature<metapc_handle_op_ret_addr_1>()).get();

        m_handle_operand_ret_addrs[1] = hat::find_pattern(m_proc_mod_text_section,
            hat::compile_signature<metapc_handle_op_ret_addr_2>()).get();

        if (std::ranges::contains(m_handle_operand_ret_addrs, nullptr)) {
            warning("FastAnalysis may not support this IDA version (signature dead)");
            return false;
        }

        m_xrefblk_hook = safetyhook::create_inline(xrefblk_t_first_to, xrefblk_t_first_to_hook);
        auto enable_result = m_xrefblk_hook.enable();
#else
        auto pattern = hat::compile_signature<metapc_hook_sig>();

        hat::scan_result result = hat::find_pattern(m_proc_mod_text_section, pattern,
            hat::scan_alignment::X16, hat::scan_hint::x86_64);

        if (!result.has_result()) {
            warning("FastAnalysis may not support this IDA version (signature dead)");
            return false;
        }

        m_metapc_hook = safetyhook::create_inline(result.get(), metapc_has_write_dref_hook);
        auto enable_result = m_metapc_hook.enable();
#endif

        if (!enable_result.has_value()) {
            warning("Failed to enable hook, FastAnalysis will not function");
            return false;
        }

        return true;
    }

    static bool get_section_bytes(const char* name, std::vector<std::byte>& bytes, ea_t& start_ea) {
        segment_t* segment = get_segm_by_name(name);

        if (segment == nullptr)
            return false;

        auto min_ea = segment->start_ea;
        auto binary_size = segment->size();

        bytes = {};
        bytes.resize(binary_size);

        msg("FastAnalysis: Getting %lld bytes from IDA (%s)\n", binary_size, name);
        auto start_time = std::chrono::high_resolution_clock::now();
        ssize_t res = get_bytes(bytes.data(),
            static_cast<ssize_t>(binary_size),
            min_ea);
        auto end_time = std::chrono::high_resolution_clock::now();
        msg("FastAnalysis: Took %d ms\n", std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time).count());

        //assert(res == binary_size);

        start_ea = segment->start_ea;

        return true;
    }

    bool get_target_sections_bytes() {
        // TODO: instead, get all sections with executable code and have an option to search the entire binary regardless of whether or not a "text" section is present

        if (!get_section_bytes(".text", m_target_text_section_bytes, m_text_start_ea)) {
            if (!get_section_bytes("__text", m_target_text_section_bytes, m_text_start_ea)) {
                msg("FastAnalysis may not support this target: no .text section or equivalent found.\n");
                return false;
            }
        }

        return true;
    }

    void scan_for_refs(bool is_arm) {
        if (m_scanned_for_refs)
            return;

        if (!get_target_sections_bytes()) {
            msg("FastAnalysis: Failed to get target text section bytes\n");
            m_active = false;
            return;
        }

        size_t section_size = m_target_text_section_bytes.size();

        uint32_t num_threads = std::thread::hardware_concurrency();
        size_t size_per_division = section_size / num_threads;

        auto start_time = std::chrono::high_resolution_clock::now();

        std::vector<std::future<std::unordered_set<uintptr_t>>> threads;

        const std::byte* division_begin = m_target_text_section_bytes.data();

        for (int i = 0; i < num_threads; i++) {
            const std::byte* division_end = division_begin + size_per_division;

            if (i != num_threads - 1) {
                // make sure we aren't cutting into the middle of an instruction
                ea_t original_ea = division_end - m_target_text_section_bytes.data() + m_text_start_ea;
                ea_t n = next_not_tail(original_ea);
                division_end += n - original_ea;
            }

            threads.emplace_back(std::async(std::launch::async, [=, text_start = m_text_start_ea] {
                return RefScanner::find_write_drefs(is_arm ? RefScanner::AARCH64 : RefScanner::X86_64, text_start + i * size_per_division,
                    division_begin, division_end);
            }));

            division_begin = division_end;
        }

        for (auto& thread : threads) {
            auto set = thread.get();
            m_write_drefs_to.merge(set);
        }

        auto end_time = std::chrono::high_resolution_clock::now();

        msg("FastAnalysis (%s): finding %d write drefs took %d ms\n", is_arm ? "arm64" : "x86-64", m_write_drefs_to.size(),
            std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time).count());

        m_scanned_for_refs = true;

        // Save some memory now that we don't need the bytes anymore
        m_target_text_section_bytes.clear();
    }

    bool m_active = false;
    bool m_scanned_for_refs = false;

#ifdef HOOK_XREFBLK
    std::array<void*, 2> m_handle_operand_ret_addrs{};
    safetyhook::InlineHook m_xrefblk_hook{};
#endif

    safetyhook::InlineHook m_metapc_hook{};
    safetyhook::InlineHook m_arm_has_write_dref_hook{};
    std::optional<hat::process::module> m_proc_mod;
    std::optional<hat::process::module> m_ida_mod;
    std::span<std::byte> m_proc_mod_text_section;
    std::span<std::byte> m_ida_mod_text_section;

    std::vector<std::byte> m_target_text_section_bytes;
    std::unordered_set<uintptr_t> m_write_drefs_to;
    ea_t m_text_start_ea{};

    // Checks if there's a write data xref to the target address
    // where to find this: pc.dll/.so, pc_t vtable -> pc_t::on_event, case ev_emu_insn -> pc_t::emu -> handle_operand
    static bool metapc_has_write_dref_hook(pc_t* proc, ea_t target_addr) {
        auto plugin = SINGLETON;
        if (!plugin->m_active) {
            return plugin->m_metapc_hook.call<bool>(proc, target_addr);
        }

        if (!plugin->m_scanned_for_refs) {
            plugin->scan_for_refs(false);
        }

        return plugin->m_write_drefs_to.contains(target_addr);
    }

    // generic function in ida.dll, probably doesn't only apply to arm but we use it as such
    // called twice in reg_finder_emulate_mem_read
    static bool arm_has_write_dref_hook(ea_t target_addr) {
        auto plugin = SINGLETON;
        if (!plugin->m_active) {
            return plugin->m_arm_has_write_dref_hook.call<bool>(target_addr);
        }

        if (!plugin->m_scanned_for_refs) {
            plugin->scan_for_refs(true);
        }

        return plugin->m_write_drefs_to.contains(target_addr);
    }

    // (linux only)
    // The above functions are inlined on pc.so, so we instead hook this and check return address
#ifdef HOOK_XREFBLK
    static bool xrefblk_t_first_to_hook(xrefblk_t* this_, ea_t to, int flags) {
        auto plugin = SINGLETON;
        if (!plugin->m_active) {
            return plugin->m_xrefblk_hook.call<bool>(this_, to, flags);
        }

        void* return_address = __builtin_return_address(0);

        if (flags == XREF_DATA && std::ranges::contains(plugin->m_handle_operand_ret_addrs, return_address))
        {
            if (!plugin->m_scanned_for_refs) {
                plugin->scan_for_refs(false);
            }

            if (!plugin->m_write_drefs_to.contains(to)) {
                return false;
            }

            // break the loop
            this_->type = dr_W;
            return true;
        }
        return plugin->m_xrefblk_hook.call<bool>(this_, to, flags);
    }
#endif
};

plugmod_t* idaapi init() {
    return FastAnalysisPlugin::SINGLETON = new FastAnalysisPlugin;
}

plugin_t PLUGIN = {
    IDP_INTERFACE_VERSION,
    PLUGIN_PROC,
    init,
    nullptr,
    nullptr,
    "Speeds up IDA Auto-Analysis",
    nullptr,
    "FastAnalysis",
    nullptr
};
