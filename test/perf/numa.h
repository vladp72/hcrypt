// numa.h : Include file for standard system include files,
// or project specific include files.

#pragma once

#include <windows.h>

#define NUMA_MAKE_SYSTEM_ERROR(E, T)                     \
    std::system_error {                                  \
        static_cast<int>(E), std::system_category(), (T) \
    }

namespace numa {
    //
    // for documentation search for
    // "Supporting Systems That Have More Than 64 Processors"
    // or MoreThan64proc.docx
    //
    class cpu_info {
    public:
        //
        // Utility class that does not have any instances
        //
        cpu_info() = delete;
        ~cpu_info() = delete;
        cpu_info(cpu_info const &) = delete;
        cpu_info(cpu_info &&) = delete;

        using cbuffer = std::vector<char>;

        using peocess_group_affinity_array = std::vector<USHORT>;
        using system_cpu_information_array = std::vector<USHORT>;

        using idle_processor_cycle_time_array = std::vector<ULONGLONG>;

        using cpu_mask_array = std::vector<ULONGLONG>;

        //-----------------
        //
        // Group of function that returns limits that helps
        // to estimate number of per CPU structures that app
        // needs to allocate
        //
        //-----------------

        //
        // Maximum number of processors groups
        //
        static USHORT get_group_maximum_processor_group_count() {
            USHORT processor_group_count{GetMaximumProcessorGroupCount()};
            if (!processor_group_count) {
                throw NUMA_MAKE_SYSTEM_ERROR(
                    GetLastError(), "GetMaximumProcessorGroupCount failed");
            }
            return processor_group_count;
        }
        //
        // Highest number of NUMA nodes on this system
        //
        static ULONG get_highest_numa_number() {
            ULONG result{0};
            if (!GetNumaHighestNodeNumber(&result)) {
                throw NUMA_MAKE_SYSTEM_ERROR(GetLastError(), "GetNumaHighestNodeNumber failed");
            }
            return result;
        }
        //
        // Maximum number of processors per group or system
        //
        static ULONG get_group_maximum_processor_count(USHORT group_number) {
            ULONG processor_count{GetMaximumProcessorCount(group_number)};
            if (!processor_count) {
                throw NUMA_MAKE_SYSTEM_ERROR(GetLastError(), "GetMaximumProcessorCount failed");
            }
            return processor_count;
        }
        //
        // Maximum number of processors in the system
        //
        static ULONG get_system_maximum_processor_count() {
            return get_group_maximum_processor_count(ALL_PROCESSOR_GROUPS);
        }
        //
        // Number of active processors groups
        //
        static USHORT get_active_processor_group_count() {
            USHORT group_count{GetActiveProcessorGroupCount()};
            if (!group_count) {
                throw NUMA_MAKE_SYSTEM_ERROR(
                    GetLastError(), "GetActiveProcessorGroupCount failed");
            }
            return group_count;
        }
        //
        // Number of active logical processors in a group or system
        //
        static ULONG get_group_active_processor_count(USHORT grup_number) {
            ULONG processor_count{GetActiveProcessorCount(grup_number)};
            if (!processor_count) {
                throw NUMA_MAKE_SYSTEM_ERROR(GetLastError(), "GetActiveProcessorCount failed");
            }
            return processor_count;
        }
        //
        // Number of active logical processors in the system
        //
        static ULONG get_system_active_processor_count() {
            return get_group_active_processor_count(ALL_PROCESSOR_GROUPS);
        }

        //-----------------
        //
        // Helper functions CPU mask array
        //
        //-----------------

        //
        // Remove any groups from the tail that do not have any
        // CPU set
        //
        static void cpu_set_truncate_unused_groups(cpu_mask_array &cpu_mask) {
            while (!cpu_mask.empty()) {
                if (cpu_mask.back()) {
                    break;
                } else {
                    cpu_mask.pop_back();
                }
            }
        }

        static bool cpu_set_has_cpu(USHORT cpu_group_number,
                                    USHORT cpu_index_in_group,
                                    cpu_mask_array const &cpu_mask) {
            size_t min_array_zize{cpu_group_number + 1U};
            if (cpu_mask.size() < min_array_zize) {
                return false;
            }
            return (cpu_mask[cpu_group_number] & (1ULL << cpu_index_in_group));
        }

        static void cpu_set_add_cpu(USHORT cpu_group_number,
                                    USHORT cpu_index_in_group,
                                    cpu_mask_array &cpu_mask) {
            size_t min_array_zize{cpu_group_number + 1U};
            if (cpu_mask.size() < min_array_zize) {
                cpu_mask.resize(min_array_zize);
            }
            cpu_mask[cpu_group_number] |= (1ULL << cpu_index_in_group);
        }

        static void cpu_set_remove_cpu(USHORT cpu_group_number,
                                       USHORT cpu_index_in_group,
                                       cpu_mask_array &cpu_mask) {
            size_t min_array_zize{cpu_group_number + 1U};
            if (cpu_mask.size() < min_array_zize) {
                return;
            }
            cpu_mask[cpu_group_number] &= ~(1ULL << cpu_index_in_group);
        }

        //-----------------
        //
        // Returns information about available CPU set
        //
        //-----------------

        static cbuffer get_system_cpu_information(HANDLE process_handle = 0) {
            ULONG buffer_size{sizeof(SYSTEM_CPU_SET_INFORMATION)};
            cbuffer result;

            for (;;) {
                result.resize(buffer_size);
                if (GetSystemCpuSetInformation(
                        reinterpret_cast<SYSTEM_CPU_SET_INFORMATION *>(&result[0]),
                        buffer_size,
                        &buffer_size,
                        process_handle,
                        0)) {
                    break;
                } else {
                    DWORD error = GetLastError();
                    if (ERROR_INSUFFICIENT_BUFFER != error) {
                        throw NUMA_MAKE_SYSTEM_ERROR(error, "GetSystemCpuSetInformation failed");
                    }
                }
            }
            result.resize(buffer_size);
            return result;
        }

        //
        // Enumirates over the buffer that contains result of
        // get_logical_processor_information, and calls a functor for each
        // element found in the buffer.
        //
        template<typename F>
        static void find_first_system_cpu_information_block(cbuffer const &info,
                                                            F const &fn) {
            size_t remaining_buffer_size{info.size()};
            SYSTEM_CPU_SET_INFORMATION const *current_info{
                reinterpret_cast<SYSTEM_CPU_SET_INFORMATION const *>(info.data())};

            for (;;) {
                if (remaining_buffer_size <
                    RTL_SIZEOF_THROUGH_FIELD(SYSTEM_CPU_SET_INFORMATION, Size)) {
                    break;
                }

                if (!fn(*current_info, remaining_buffer_size)) {
                    break;
                }

                if (0 == current_info->Size) {
                    break;
                }

                remaining_buffer_size -= current_info->Size;
                current_info = reinterpret_cast<SYSTEM_CPU_SET_INFORMATION const *>(
                    reinterpret_cast<char const *>(current_info) + current_info->Size);
            }
        }

        template<typename F>
        static void find_first_system_cpu_information_block(F const &fn,
                                                            HANDLE process_handle = 0) {
            cbuffer const info{get_system_cpu_information(process_handle)};
            find_first_system_cpu_information_block(info, fn);
        }

        //-----------------
        //
        // Group of function that allows query CPU configuration
        // including proximity and cache information.
        // It returns a buffer of variable lengths structures.
        // Use find_first_processor_information_block to iterate
        // over entries in the buffer.
        //
        //-----------------

        //
        // Queries requested information, and reallocates buffer as nessesary
        //
        static cbuffer get_logical_processor_information(LOGICAL_PROCESSOR_RELATIONSHIP relationship_type) {
            ULONG buffer_size{4096};
            cbuffer buf;

            for (;;) {
                buf.resize(buffer_size);
                if (GetLogicalProcessorInformationEx(
                        relationship_type,
                        reinterpret_cast<PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX>(&buf[0]),
                        &buffer_size)) {
                    break;
                } else {
                    ULONG error{GetLastError()};
                    if (ERROR_INSUFFICIENT_BUFFER != error) {
                        throw NUMA_MAKE_SYSTEM_ERROR(
                            error, "GetLogicalProcessorInformationEx failed");
                    }
                }
            }
            buf.resize(buffer_size);
            return buf;
        }

        //
        // Enumirates over the buffer that contains result of
        // get_logical_processor_information, and calls a functor for each
        // element found in the buffer.
        //
        template<typename F>
        static void find_first_processor_information_block(cbuffer const &info, F const &fn) {
            size_t remaining_buffer_size{info.size()};
            SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX const *current_info{
                reinterpret_cast<SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX const *>(info.data())};

            for (;;) {
                if (remaining_buffer_size <
                    RTL_SIZEOF_THROUGH_FIELD(SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX, Size)) {
                    break;
                }

                if (!fn(*current_info, remaining_buffer_size)) {
                    break;
                }

                if (0 == current_info->Size) {
                    break;
                }

                remaining_buffer_size -= current_info->Size;
                current_info = reinterpret_cast<SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX const *>(
                    reinterpret_cast<char const *>(current_info) + current_info->Size);
            }
        }

        //
        // Combines together call to get_logical_processor_information
        // and enumiration over a result.
        //
        template<typename F>
        static void find_first_processor_information_block(LOGICAL_PROCESSOR_RELATIONSHIP relationship_type,
                                                           F const &fn) {
            cbuffer const info{get_logical_processor_information(relationship_type)};
            find_first_processor_information_block(info, fn);
        }

        //
        // Returns amount of memory available on a NUMA node
        //
        static ULONGLONG get_numa_available_memory(USHORT node) {
            ULONGLONG result{0};
            if (!GetNumaAvailableMemoryNodeEx(node, &result)) {
                throw NUMA_MAKE_SYSTEM_ERROR(
                    GetLastError(), "GetNumaAvailableMemoryNodeEx failed");
            }
            return result;
        }

        //
        // Mask of all logical processors in the node
        // It returns information about all processors, regardless
        // what group they belong to.
        //
        static GROUP_AFFINITY get_numa_node_processor_mask(USHORT node) {
            GROUP_AFFINITY result{0};
            if (!GetNumaNodeProcessorMaskEx(node, &result)) {
                throw NUMA_MAKE_SYSTEM_ERROR(GetLastError(), "GetNumaNodeProcessorMaskEx failed");
            }
            return result;
        }

        //
        // Returns numa node for a processor
        //
        static USHORT get_processor_numa_node(PROCESSOR_NUMBER const &processor) {
            USHORT result{0};
            if (!GetNumaProcessorNodeEx(const_cast<PROCESSOR_NUMBER *>(&processor), &result)) {
                throw NUMA_MAKE_SYSTEM_ERROR(GetLastError(), "GetNumaProcessorNodeEx failed");
            }
            return result;
        }

        //
        // Returns numa node for the given proximity id.
        //
        static USHORT get_proximity_id_numa_node(ULONG proximity_id) {
            USHORT result{0};
            if (!GetNumaProximityNodeEx(proximity_id, &result)) {
                throw NUMA_MAKE_SYSTEM_ERROR(GetLastError(), "GetNumaProximityNodeEx failed");
            }
            return result;
        }

        //-----------------
        //
        // Information about processor current thread is runnig on
        //
        //-----------------

        //
        // Information about the processor current thread is running on
        //
        static PROCESSOR_NUMBER get_current_processor_number() noexcept {
            PROCESSOR_NUMBER processor_number{0};
            GetCurrentProcessorNumberEx(&processor_number);
            return processor_number;
        }

        //-----------------
        //
        // Information about processor and thread affinity
        //
        //-----------------

        //
        // Returns information about all groups threads of this process have
        // affinity to.
        //
        static peocess_group_affinity_array get_process_group_affinity(
            HANDLE process_handle = GetCurrentProcess()) {
            USHORT group_count{2};
            peocess_group_affinity_array result;

            for (;;) {
                result.resize(group_count);
                if (GetProcessGroupAffinity(process_handle, &group_count, result.data())) {
                    break;
                } else {
                    DWORD error = GetLastError();
                    if (ERROR_INSUFFICIENT_BUFFER != error) {
                        throw NUMA_MAKE_SYSTEM_ERROR(error, "GetProcessGroupAffinity failed");
                    }
                }
            }
            result.resize(group_count);
            return result;
        }
        //
        // Information about group given thread has affinity to
        //
        static GROUP_AFFINITY get_thread_group_affinity(HANDLE thread_handle = GetCurrentThread()) {
            GROUP_AFFINITY result;
            if (!GetThreadGroupAffinity(thread_handle, &result)) {
                throw NUMA_MAKE_SYSTEM_ERROR(GetLastError(), "GetThreadGroupAffinity failed");
            }
            return result;
        }

        //
        // Assigns thread to a new affinity group, and returns previous affinity
        // group this thread was assigned to
        //
        static GROUP_AFFINITY set_thread_group_affinity(GROUP_AFFINITY const &new_affinity_group,
                                                        HANDLE thread_handle = GetCurrentThread()) {
            GROUP_AFFINITY prev_affinity_group;
            if (!SetThreadGroupAffinity(thread_handle, &new_affinity_group, &prev_affinity_group)) {
                throw NUMA_MAKE_SYSTEM_ERROR(GetLastError(), "SetThreadGroupAffinity failed");
            }
            return prev_affinity_group;
        }

        //
        // Returns thread ideal processor
        //
        static PROCESSOR_NUMBER get_thread_ideal_processor(HANDLE thread_handle = GetCurrentThread()) {
            PROCESSOR_NUMBER ideal_rocessor;
            if (!GetThreadIdealProcessorEx(thread_handle, &ideal_rocessor)) {
                throw NUMA_MAKE_SYSTEM_ERROR(GetLastError(), "GetThreadIdealProcessorEx failed");
            }
            return ideal_rocessor;
        }

        //
        // Sets thread affinity processor
        //
        static PROCESSOR_NUMBER set_thread_ideal_processor(PROCESSOR_NUMBER const &new_ideal_rocessor,
                                                           HANDLE thread_handle = GetCurrentThread()) {
            PROCESSOR_NUMBER prev_ideal_rocessor;
            if (!SetThreadIdealProcessorEx(thread_handle,
                                           const_cast<PROCESSOR_NUMBER *>(&new_ideal_rocessor),
                                           &prev_ideal_rocessor)) {
                throw NUMA_MAKE_SYSTEM_ERROR(GetLastError(), "SetThreadIdealProcessorEx failed");
            }
            return prev_ideal_rocessor;
        }

        //-----------------
        //
        // Processor statistics
        //
        //-----------------

        //
        // Returns information about all groups threads of this process have
        // affinity to.
        //
        static idle_processor_cycle_time_array get_idle_rocessor_cycle_time(USHORT processor_group) {
            ULONG buffer_size{get_group_maximum_processor_count(processor_group) *
                              sizeof(idle_processor_cycle_time_array::value_type)};
            idle_processor_cycle_time_array result;

            for (;;) {
                result.resize(buffer_size / sizeof(idle_processor_cycle_time_array::value_type));

                if (QueryIdleProcessorCycleTimeEx(
                        processor_group, &buffer_size, result.data())) {
                    break;
                } else {
                    DWORD error = GetLastError();
                    if (ERROR_INSUFFICIENT_BUFFER != error) {
                        throw NUMA_MAKE_SYSTEM_ERROR(
                            error, "QueryIdleProcessorCycleTimeEx failed");
                    }
                }
            }
            result.resize(buffer_size / sizeof(idle_processor_cycle_time_array::value_type));
            return result;
        }

        //-----------------
        //
        // Few helper function to convert enumiration value names to strings
        //
        //-----------------

        static wchar_t const *processor_relationship_to_wstr(
            LOGICAL_PROCESSOR_RELATIONSHIP processor_relationship) noexcept {
            wchar_t const *str{L"unknows relationship type"};
            switch (processor_relationship) {
            case RelationProcessorCore:
                str = L"RelationProcessorCore";
                break;
            case RelationNumaNode:
                str = L"RelationNumaNode";
                break;
            case RelationCache:
                str = L"RelationCache";
                break;
            case RelationProcessorPackage:
                str = L"RelationProcessorPackage";
                break;
            case RelationGroup:
                str = L"RelationGroup";
                break;
            case RelationAll:
                str = L"RelationAll";
                break;
            }
            return str;
        }

        static wchar_t const *processor_cahe_type_to_wstr(PROCESSOR_CACHE_TYPE processor_cache_type) noexcept {
            wchar_t const *str{L"unknows cache type"};
            switch (processor_cache_type) {
            case CacheUnified:
                str = L"CacheUnified";
                break;
            case CacheInstruction:
                str = L"CacheInstruction";
                break;
            case CacheData:
                str = L"CacheData";
                break;
            case CacheTrace:
                str = L"CacheTrace";
                break;
            }
            return str;
        }

        static wchar_t const *cpu_set_information_type_to_wstr(
            CPU_SET_INFORMATION_TYPE cpu_set_information_type) noexcept {
            wchar_t const *str{L"unknows cpu set information type"};
            switch (cpu_set_information_type) {
            case CpuSetInformation:
                str = L"CpuSetInformation";
                break;
            }
            return str;
        }
        //-----------------
        //
        // Convinience function
        //
        //-----------------

        static KAFFINITY processor_id_to_bitmap(ULONG processor_number) {
            if (processor_number >= std::numeric_limits<KAFFINITY>::digits) {
                throw NUMA_MAKE_SYSTEM_ERROR(ERROR_INVALID_PARAMETER, "Invalid processor number");
            }
            return (1ULL << processor_number);
        }

        template<typename F>
        static void find_first_active_group(F const &fn) {
            USHORT active_processor_group_count{get_active_processor_group_count()};
            for (USHORT idx = 0; idx < active_processor_group_count; ++idx) {
                if (!fn(idx)) {
                    break;
                }
            }
        }

        template<typename F>
        static void find_first_active_processor_in_group(USHORT group_number, F const &fn) {
            ULONG active_processor_count{get_group_active_processor_count()};
            for (ULONG idx = 0; idx < active_processor_count; ++idx) {
                if (!fn(group_number, idx)) {
                    break;
                }
            }
        }

        template<typename F>
        static void find_first_active_processor(F const &fn) {
            find_first_active_group([&fn](USHORT group_number) -> bool {
                bool continue_iterating{true};
                find_first_active_processor_in_group(
                    group_number,
                    [&fn, &continue_iterating](USHORT group_number, ULONG processor_number) -> bool {
                        continue_iterating = fn(group_number, processor_number);
                        return continue_iterating;
                    });
                return continue_iterating;
            });
        }

        template<typename F>
        static void find_first_numa_node(F const &fn) {
            USHORT highest_numa_number{static_cast<USHORT>(get_highest_numa_number())};
            for (USHORT idx = 0; idx < highest_numa_number; ++idx) {
                if (!fn(idx)) {
                    break;
                }
            }
        }
    };
} // namespace numa

//-----------------
//
// On a machine PROCESSOR_NUMBER form is a
// set with a total order
//
//-----------------

inline bool operator==(PROCESSOR_NUMBER const &lhs, PROCESSOR_NUMBER const &rhs) {
    return lhs.Group == rhs.Group && lhs.Number == rhs.Number;
}

inline bool operator!=(PROCESSOR_NUMBER const &lhs, PROCESSOR_NUMBER const &rhs) {
    return !operator==(lhs, rhs);
}

inline bool operator<(PROCESSOR_NUMBER const &lhs, PROCESSOR_NUMBER const &rhs) {
    return lhs.Group < rhs.Group
               ? true
               : lhs.Group == rhs.Group ? lhs.Number < rhs.Number : false;
}

inline bool operator>=(PROCESSOR_NUMBER const &lhs, PROCESSOR_NUMBER const &rhs) {
    return !operator<(lhs, rhs);
}

inline bool operator>(PROCESSOR_NUMBER const &lhs, PROCESSOR_NUMBER const &rhs) {
    return lhs.Group > rhs.Group
               ? true
               : lhs.Group == rhs.Group ? lhs.Number > rhs.Number : false;
}

inline bool operator<=(PROCESSOR_NUMBER const &lhs, PROCESSOR_NUMBER const &rhs) {
    return !operator>(lhs, rhs);
}

namespace numa {
    // typedef struct _PROCESSOR_NUMBER {
    //	WORD   Group;
    //	BYTE  Number;
    //	BYTE  Reserved;
    //} PROCESSOR_NUMBER, * PPROCESSOR_NUMBER;

    inline void print(int padding, size_t idx, PROCESSOR_NUMBER const &info) {
        printf("%*c[%zi] PROCESSOR_NUMBER(%zi) {\n", padding, ' ', idx, sizeof(info));
        printf("%*cGroup  = %hi, 0x%hx\n", padding + 2, ' ', info.Group, info.Group);
        printf("%*cNumber = %i, 0x%x\n", padding + 2, ' ', info.Number, info.Number);
        printf("%*c}\n", padding, ' ');
    }

    // typedef struct _GROUP_AFFINITY {
    //	KAFFINITY Mask;
    //	WORD   Group;
    //	WORD   Reserved[3];
    //} GROUP_AFFINITY, * PGROUP_AFFINITY;

    inline void print(int padding, size_t idx, GROUP_AFFINITY const &info) {
        printf("%*c[%zi] GROUP_AFFINITY(%zi) {\n", padding, ' ', idx, sizeof(info));
        printf("%*cMask        = %zi, 0x%zx\n", padding + 2, ' ', info.Mask, info.Mask);
        printf("%*cGroup       = %hi, 0x%hx\n", padding + 2, ' ', info.Group, info.Group);
        // printf("%*cReserved[3] = {0x%x, 0x%x, 0x%x}\n", padding + 2, ' ', info.Reserved[0], info.Reserved[1], info.Reserved[2]);
        printf("%*c}\n", padding, ' ');
    }

    // typedef struct _PROCESSOR_RELATIONSHIP {
    //	BYTE  Flags;
    //	BYTE  EfficiencyClass;
    //	BYTE  Reserved[20];
    //	WORD   GroupCount;
    //	_Field_size_(GroupCount) GROUP_AFFINITY GroupMask[ANYSIZE_ARRAY];
    //} PROCESSOR_RELATIONSHIP, * PPROCESSOR_RELATIONSHIP;

    inline void print(int padding, size_t idx, PROCESSOR_RELATIONSHIP const &info) {
        printf("%*c[%zi] PROCESSOR_RELATIONSHIP(%zi) {\n", padding, ' ', idx, sizeof(info));
        printf("%*cFlags           = %i, 0x%x, %s\n",
               padding + 2,
               ' ',
               info.Flags,
               info.Flags,
               LTP_PC_SMT & info.Flags ? "LTP_PC_SMT" : "");
        printf("%*cEfficiencyClass = %i, 0x%x\n", padding + 2, ' ', info.EfficiencyClass, info.EfficiencyClass);
        printf("%*cGroupCount      = %i\n", padding + 2, ' ', info.GroupCount);
        // BYTE Reserved[20];
        for (int child_idx = 0; child_idx < info.GroupCount; ++child_idx) {
            print(padding + 2, child_idx, info.GroupMask[child_idx]);
        }
        printf("%*c}\n", padding, ' ');
    }

    // typedef struct _NUMA_NODE_RELATIONSHIP {
    //	DWORD NodeNumber;
    //	BYTE  Reserved[20];
    //	GROUP_AFFINITY GroupMask;
    //} NUMA_NODE_RELATIONSHIP, * PNUMA_NODE_RELATIONSHIP;

    inline void print(int padding, size_t idx, NUMA_NODE_RELATIONSHIP const &info) {
        printf("%*c[%zi] NUMA_NODE_RELATIONSHIP(%zi) {\n", padding, ' ', idx, sizeof(info));
        printf("%*cNodeNumber = %i\n", padding + 2, ' ', info.NodeNumber);
        // BYTE Reserved[20];
        print(padding + 2, 0, info.GroupMask);
        printf("%*c}\n", padding, ' ');
    }

    // typedef struct _CACHE_RELATIONSHIP {
    //	BYTE                 Level;
    //	BYTE                 Associativity;
    //	WORD                 LineSize;
    //	DWORD                CacheSize;
    //	PROCESSOR_CACHE_TYPE Type;
    //	BYTE                 Reserved[20];
    //	GROUP_AFFINITY       GroupMask;
    //} CACHE_RELATIONSHIP, * PCACHE_RELATIONSHIP;

    inline void print(int padding, size_t idx, CACHE_RELATIONSHIP const &info) {
        printf("%*c[%zi] CACHE_RELATIONSHIP(%zi) {\n", padding, ' ', idx, sizeof(info));
        printf("%*cLevel         = %i, 0x%x\n", padding + 2, ' ', info.Level, info.Level);
        printf("%*cAssociativity = %i, 0x%x\n", padding + 2, ' ', info.Associativity, info.Associativity);
        printf("%*cLineSize      = %i, 0x%x\n", padding + 2, ' ', info.LineSize, info.LineSize);
        printf("%*cCacheSize     = %i, 0x%x\n", padding + 2, ' ', info.CacheSize, info.CacheSize);
        printf("%*cType          = %i, %S\n",
               padding + 2,
               ' ',
               info.Type,
               cpu_info::processor_cahe_type_to_wstr(info.Type));
        // BYTE Reserved[20];
        print(padding + 2, 0, info.GroupMask);
        printf("%*c}\n", padding, ' ');
    }

    // typedef struct _PROCESSOR_GROUP_INFO {
    //	BYTE  MaximumProcessorCount;
    //	BYTE  ActiveProcessorCount;
    //	BYTE  Reserved[38];
    //	KAFFINITY ActiveProcessorMask;
    //} PROCESSOR_GROUP_INFO, * PPROCESSOR_GROUP_INFO;

    inline void print(int padding, size_t idx, PROCESSOR_GROUP_INFO const &info) {
        printf("%*c[%zi] GROUP_RELATIONSHIP(%zi) {\n", padding, ' ', idx, sizeof(info));
        printf("%*cMaximumProcessorCount = %i\n", padding + 2, ' ', info.MaximumProcessorCount);
        printf("%*cActiveProcessorCount  = %i\n", padding + 2, ' ', info.ActiveProcessorCount);
        printf("%*cActiveProcessorMask   = 0x%zx\n", padding + 2, ' ', info.ActiveProcessorMask);
        printf("%*c}\n", padding, ' ');
    }

    //
    // typedef struct _GROUP_RELATIONSHIP {
    //	WORD   MaximumGroupCount;
    //	WORD   ActiveGroupCount;
    //	BYTE  Reserved[20];
    //	PROCESSOR_GROUP_INFO GroupInfo[ANYSIZE_ARRAY];
    //} GROUP_RELATIONSHIP, * PGROUP_RELATIONSHIP;

    inline void print(int padding, size_t idx, GROUP_RELATIONSHIP const &info) {
        printf("%*c[%zi] GROUP_RELATIONSHIP(%zi) {\n", padding, ' ', idx, sizeof(info));
        printf("%*cMaximumGroupCount = %i\n", padding + 2, ' ', info.MaximumGroupCount);
        printf("%*cActiveGroupCount  = %i\n", padding + 2, ' ', info.ActiveGroupCount);
        // BYTE Reserved[20];
        for (int child_idx = 0; child_idx < info.ActiveGroupCount; ++child_idx) {
            print(padding + 2, child_idx, info.GroupInfo[child_idx]);
        }
        printf("%*c}\n", padding, ' ');
    }

    //_Struct_size_bytes_(Size) struct _SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX
    //{ 	LOGICAL_PROCESSOR_RELATIONSHIP Relationship; 	DWORD Size; 	union { PROCESSOR_RELATIONSHIP
    // Processor; 		NUMA_NODE_RELATIONSHIP NumaNode; 		CACHE_RELATIONSHIP Cache; GROUP_RELATIONSHIP
    // Group; 	} DUMMYUNIONNAME;
    //};

    inline void print_processor_information(int padding, LOGICAL_PROCESSOR_RELATIONSHIP relationship_type) {
        size_t idx{0};
        cpu_info::find_first_processor_information_block(
            relationship_type,
            [padding, &idx](SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX const &info,
                            size_t size) -> bool {
                printf("%*c[%zi] SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX(%zi, "
                       "%zi) {\n",
                       padding,
                       ' ',
                       idx,
                       sizeof(info),
                       size);
                printf("%*cRelationship = %i, %S\n",
                       padding + 2,
                       ' ',
                       info.Relationship,
                       cpu_info::processor_relationship_to_wstr(info.Relationship));
                printf("%*cSize = %i\n", padding + 2, ' ', info.Size);
                switch (info.Relationship) {
                case RelationProcessorCore:
                    //[[fallthrough]]
                case RelationProcessorPackage:
                    print(padding + 2, 0, info.Processor);
                    break;
                case RelationNumaNode:
                    print(padding + 2, 0, info.NumaNode);
                    break;
                case RelationCache:
                    print(padding + 2, 0, info.Cache);
                    break;
                case RelationGroup:
                    print(padding + 2, 0, info.Group);
                    break;
                case RelationAll:
                default:
                    printf("%*c unexpected type %zi, size %zi\n", padding, ' ', idx, size);
                    break;
                }
                printf("%*c}\n", padding, ' ');
                return true;
            });
    }

    inline void print(int padding, size_t idx, SYSTEM_CPU_SET_INFORMATION const &info, size_t buffer_size) {
        printf("%*c[%zi] SYSTEM_CPU_SET_INFORMATION(%zi, %zi) {\n", padding, ' ', idx, sizeof(info), buffer_size);
        printf("%*cSize                     = %i\n", padding + 2, ' ', info.Size);
        printf("%*cType                     = %i, %S\n",
               padding + 2,
               ' ',
               info.Type,
               cpu_info::cpu_set_information_type_to_wstr(info.Type));
        switch (info.Type) {
        case CpuSetInformation:
            printf("%*cId                       = %u, 0x%x\n",
                   padding + 2,
                   ' ',
                   info.CpuSet.Id,
                   info.CpuSet.Id);
            printf("%*cGroup                    = %u, 0x%x\n",
                   padding + 2,
                   ' ',
                   info.CpuSet.Group,
                   info.CpuSet.Group);
            printf("%*cLogicalProcessorIndex    = %u, 0x%x\n",
                   padding + 2,
                   ' ',
                   static_cast<unsigned long>(info.CpuSet.LogicalProcessorIndex),
                   static_cast<unsigned long>(info.CpuSet.LogicalProcessorIndex));
            printf("%*cCoreIndex                = %u, 0x%x\n",
                   padding + 2,
                   ' ',
                   static_cast<unsigned long>(info.CpuSet.CoreIndex),
                   static_cast<unsigned long>(info.CpuSet.CoreIndex));
            printf("%*cLastLevelCacheIndex      = %u, 0x%x\n",
                   padding + 2,
                   ' ',
                   static_cast<unsigned long>(info.CpuSet.LastLevelCacheIndex),
                   static_cast<unsigned long>(info.CpuSet.LastLevelCacheIndex));
            printf("%*cNumaNodeIndex            = %u, 0x%x\n",
                   padding + 2,
                   ' ',
                   static_cast<unsigned long>(info.CpuSet.NumaNodeIndex),
                   static_cast<unsigned long>(info.CpuSet.NumaNodeIndex));
            printf("%*cEfficiencyClass          = %u, 0x%x\n",
                   padding + 2,
                   ' ',
                   static_cast<unsigned long>(info.CpuSet.EfficiencyClass),
                   static_cast<unsigned long>(info.CpuSet.EfficiencyClass));
            printf("%*cAllFlags                 = %u, 0x%x\n",
                   padding + 2,
                   ' ',
                   static_cast<unsigned long>(info.CpuSet.AllFlags),
                   static_cast<unsigned long>(info.CpuSet.AllFlags));
            printf("%*cParked                   = %s\n",
                   padding + 2,
                   ' ',
                   info.CpuSet.Parked ? "Y" : "N");
            printf("%*cAllocated                = %s\n",
                   padding + 2,
                   ' ',
                   info.CpuSet.Allocated ? "Y" : "N");
            printf("%*cAllocatedToTargetProcess = %s\n",
                   padding + 2,
                   ' ',
                   info.CpuSet.AllocatedToTargetProcess ? "Y" : "N");
            printf("%*cRealTime                 = %s\n",
                   padding + 2,
                   ' ',
                   info.CpuSet.RealTime ? "Y" : "N");
            printf("%*cReservedFlags            = %u, 0x%x\n",
                   padding + 2,
                   ' ',
                   static_cast<unsigned long>(info.CpuSet.ReservedFlags),
                   static_cast<unsigned long>(info.CpuSet.ReservedFlags));
            printf("%*cReserved                 = %u, 0x%x\n",
                   padding + 2,
                   ' ',
                   static_cast<unsigned long>(info.CpuSet.Reserved),
                   static_cast<unsigned long>(info.CpuSet.Reserved));
            printf("%*cSchedulingClass          = %u\n",
                   padding + 2,
                   ' ',
                   static_cast<unsigned long>(info.CpuSet.SchedulingClass));
            printf("%*cAllocationTag            = %I64u, 0x%I64x\n",
                   padding + 2,
                   ' ',
                   info.CpuSet.AllocationTag,
                   info.CpuSet.AllocationTag);
            break;
        }
        printf("%*c}\n", padding, ' ');
    }

    inline void print_processor_information(int padding = 0) {
        size_t idx{0};
        cpu_info::find_first_system_cpu_information_block(
            [padding, &idx](SYSTEM_CPU_SET_INFORMATION const &info, size_t size) -> bool {
                print(padding, idx, info, size);
                ++idx;
                return true;
            });
    }

    inline void print(int padding, cpu_info::cpu_mask_array const &info) {
        size_t idx{0};
        for (auto group_mask : info) {
            printf("%*c processor group[%zi] %I64u, 0x%I64x \n", padding, ' ', idx, group_mask, group_mask);
            ++idx;
        }
    }

    inline void print_processor_mask(int padding = 0) {
        cpu_info::cpu_mask_array cpu_mask;
        cpu_info::find_first_system_cpu_information_block(
            [padding, &cpu_mask](SYSTEM_CPU_SET_INFORMATION const &info, size_t size) -> bool {
                switch (info.Type) {
                case CpuSetInformation:
                    printf("%*cGroup = %u, 0x%x, ",
                           padding + 2,
                           ' ',
                           info.CpuSet.Group,
                           info.CpuSet.Group);
                    printf(
                        "LogicalProcessorIndex = %u, 0x%x, bitmask 0x%02I64x\n",
                        static_cast<unsigned long>(info.CpuSet.LogicalProcessorIndex),
                        static_cast<unsigned long>(info.CpuSet.LogicalProcessorIndex),
                        1ULL << info.CpuSet.LogicalProcessorIndex);

                    cpu_info::cpu_set_add_cpu(
                        info.CpuSet.Group, info.CpuSet.LogicalProcessorIndex, cpu_mask);
                    break;
                }
                return true;
            });

        print(padding, cpu_mask);
    }

    inline void print_process_affinity() {
        size_t idx{0};
        cpu_info::peocess_group_affinity_array process_group_affinity{
            cpu_info::get_process_group_affinity()};
        printf("get_process_group_affinity(this process) -> %zu\n",
               process_group_affinity.size());
        idx = 0;
        for (USHORT group : process_group_affinity) {
            printf("  group[%zu] = %hu\n", idx, group);
            ++idx;
        }
    }

    inline void print_thread_affinity() {
        printf("get_thread_group_affinity(this thread)  ->\n");
        print(2, 0, cpu_info::get_thread_group_affinity());
        printf("get_thread_ideal_processor(this thread) ->\n");
        print(2, 0, cpu_info::get_thread_ideal_processor());
        printf("get_current_processor_number()          ->\n");
        print(2, 0, cpu_info::get_current_processor_number());
    }

    inline void print_system_info() {
        printf("get_group_maximum_processor_group_count() -> %u\n",
               cpu_info::get_group_maximum_processor_group_count());
        printf("get_highest_numa_number()                 -> %hu\n",
               cpu_info::get_highest_numa_number());
        printf("get_system_maximum_processor_count()      -> %u\n",
               cpu_info::get_system_maximum_processor_count());
        printf("get_active_processor_group_count()        -> %u\n",
               cpu_info::get_active_processor_group_count());
        printf("get_system_active_processor_count()       -> %u\n",
               cpu_info::get_system_active_processor_count());

        cpu_info::find_first_numa_node([](USHORT numa_node_number) -> bool {
            try {
                ULONGLONG available_memory{cpu_info::get_numa_available_memory(numa_node_number)};
                printf("get_numa_available_memory(node = %u) -> %I64u\n",
                       numa_node_number,
                       available_memory);
                GROUP_AFFINITY affinity{cpu_info::get_numa_node_processor_mask(numa_node_number)};
                printf("get_numa_node_processor_mask_ex(node = %u) ->\n", numa_node_number);
                print(2, numa_node_number, affinity);
            } catch (std::system_error const &ex) {
                printf("get_numa_node_processor_mask(node = %u) -> Error code "
                       "= %u, %s\n",
                       numa_node_number,
                       ex.code().value(),
                       ex.what());
            }
            return true;
        });

        cpu_info::find_first_active_group([](USHORT processor_group) -> bool {
            cpu_info::idle_processor_cycle_time_array idle_rocessor_cycle_time{
                cpu_info::get_idle_rocessor_cycle_time(processor_group)};
            printf("get_idle_rocessor_cycle_time(group = %hu) -> %zu\n",
                   processor_group,
                   idle_rocessor_cycle_time.size());
            size_t idx{0};
            for (auto val : idle_rocessor_cycle_time) {
                printf("  [%zu] -> %I64u, %I64x\n", idx, val, val);
                ++idx;
            }
            return true;
        });
    }

    int test_all() {
        try {
            printf("\n---\n");
            print_system_info();

            printf("\n---\n");
            print_process_affinity();

            printf("\n---\n");
            print_thread_affinity();

            printf("\n---\n");
            print_processor_information(0, RelationAll);

            printf("\n---\n");
            print_processor_information();

            printf("\n---\n");
            print_processor_mask();

        } catch (std::system_error const &ex) {
            printf("Error code = %u, %s\n", ex.code().value(), ex.what());
        }
        return 0;
    }

} // namespace numa
