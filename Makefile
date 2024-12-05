# this is a make file for a kernel object
# see online for more information
CONFIG_MODULE_SIG=n
# will build "hello.ko"
obj-m += selir.o

# we have no file "hello.c" in this example
# therefore we specify: module hello.ko relies on
# main.c and greet.c ... it's this makefile module magic thing..
# see online resources for more information
# YOU DON'T need this IF you have *.c-file with the name of the
# final kernel module :)
selir-objs := \
	src/api/ftrace_hook_api.o \
	src/api/hook_functions_api.o \
	src/api/check_srv6.o \
	src/api/test.o \
	src/api/netlink_router.o \
	src/api/netlink_handler.o \
	src/api/option_resolver.o \
	src/structure/path_validation_structure.o \
	src/structure/path_validation_header.o \
	src/structure/namespace/namespace.o \
	src/structure/crypto/crypto_structure.o \
	src/structure/crypto/bloom_filter.o \
	src/structure/interface/interface_table.o \
	src/structure/routing/destination_info.o \
	src/structure/routing/array_based_routing_table.o \
	src/structure/routing/hash_based_routing_table.o \
	src/structure/routing/routing_calc_res.o \
	src/structure/routing/routing_table_entry.o \
	src/hooks/inet_sendmsg/impl.o \
	src/hooks/inet_sendmsg/hook.o \
	src/hooks/network_layer/ipv6/ipv6_rcv/hook.o \
	src/hooks/network_layer/ipv6/ipv6_rcv/impl.o \
	src/hooks/network_layer/ipv6/ipv6_rcv_finish/impl.o \
	src/hooks/network_layer/ipv6/ip6_rcv_finish_core/impl.o \
	src/hooks/network_layer/ipv4/ip_local_deliver/impl.o \
	src/hooks/network_layer/ipv4/ip_append_data/impl.o \
	src/hooks/network_layer/ipv4/ip_local_out/impl.o \
	src/hooks/network_layer/ipv4/ip_make_skb/impl.o \
	src/hooks/network_layer/ipv4/ip_output/impl.o \
	src/hooks/network_layer/ipv4/ip_rcv/hook.o \
	src/hooks/network_layer/ipv4/ip_rcv/impl.o \
	src/hooks/network_layer/ipv4/ip_send_check/impl.o \
	src/hooks/network_layer/ipv4/ip_send_skb/impl.o \
	src/hooks/network_layer/ipv4/ip_setup_cork/impl.o \
	src/hooks/network_layer/ipv4/ip_packet_forward/impl.o \
	src/hooks/transport_layer/tcp/tcp_v4_rcv/impl.o \
	src/hooks/transport_layer/tcp/tcp_v4_rcv/hook.o \
	src/hooks/transport_layer/tcp/tcp_rcv_established/impl.o \
	src/hooks/transport_layer/tcp/tcp_v4_do_rcv/impl.o \
	 src/hooks/transport_layer/udp/udp_rcv/impl.o \
	src/hooks/transport_layer/udp/udp_send_skb/impl.o \
	src/hooks/transport_layer/udp/udp_sendmsg/impl.o \
	src/hooks/transport_layer/udp/udp_sendmsg/hook.o \
	src/prepare/resolve_function_address.o \
	src/tools/tools.o \
	src/module_starter.o \



OUTPUT_DIR = "./build"

# 这个必须要是 headers 的绝对路径才能行
ccflags-y += -I/home/zhf/Projects/srv6/linux/selir/headers
#ccflags-y += -I/home/zhf/Projects/linux/selir/headers


all: compile
	echo "successful make"

compile:
	make -C /lib/modules/5.19.0/build/ M=$(PWD) modules

mv:
	mv .*.cmd *.ko *.o *.mod *.mod.c Module.symvers modules.order $(OUTPUT_DIR)

clean:
	rm -rf .*.cmd *.ko *.o *.mod *.mod.c Module.symvers modules.order
	# make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
