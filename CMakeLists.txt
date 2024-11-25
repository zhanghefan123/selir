cmake_minimum_required(VERSION 3.0.0 FATAL_ERROR)

project("Loadable Kernel Module" VERSION 0.1.0 LANGUAGES C)
set(CMAKE_C_STANDARD 90)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Find kernel headers
list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake")
find_package(KernelHeaders REQUIRED)


# find MODULE_LICENSE("GPL"), MODULE_AUTHOR() etc.
# thanks to "merseyviking" from stack overflow
add_definitions(-D__KERNEL__ -DMODULE)

# this is needed in order for CLion IDE to provide syntax highlightning
# this is independent from the actual kernel object that is built
add_executable(lkm
        src/api/ftrace_hook_api.c
        src/api/hook_functions_api.c
        src/api/check_srv6.c
        src/api/test.c
        src/api/netlink_router.c
        src/api/netlink_handler.c
        src/api/option_resolver.c
        src/structure/namespace.c
        src/structure/crypto_structure.c
        src/structure/bloom_filter.c
        src/structure/destination_info.c
        src/structure/path_validation_structure.c
        src/structure/source_routing_table.c
        src/structure/interface_table.c
        src/hooks/ipv6_rcv/hook.c
        src/hooks/ipv6_rcv/impl.c
        src/hooks/ipv6_rcv_finish/impl.c
        src/hooks/ip6_rcv_finish_core/impl.c
        src/hooks/tcp_v4_rcv/hook.c
        src/hooks/tcp_v4_rcv/impl.c
        src/hooks/tcp_v4_do_rcv/impl.c
        src/hooks/tcp_rcv_established/impl.c
        src/hooks/udp_sendmsg/hook.c
        src/hooks/udp_sendmsg/impl.c
        src/prepare/resolve_function_address.c
        src/tools/tools.c
        src/module_starter.c
)

set(HEADERS_DIR
        /usr/src/linux-hwe-5.19-headers-5.19.0-41/include
        /usr/src/linux-hwe-5.19-headers-5.19.0-41/arch/x86/include
        headers)

# CLion IDE will find symbols from <linux/*>
target_include_directories("lkm" PRIVATE ${HEADERS_DIR})