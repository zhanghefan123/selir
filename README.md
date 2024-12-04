# attentions:

1. makefile 之中的 ccflags-y 这个必须要是 headers 的绝对路径才能行
2. 需要在启动容器 (i.e., lir_node) 之前安装内核模块,
3. 在启动容器之后不能进行内核模块的卸载与重新装载, 因为在创建容器的时候传递了路由, 接口等信息, 重新
安装内核模块之后这些信息都将会消逝。
4. 原有的代码使用 original_code 标识


 
# tips:

1. 为了使用 linux 上一些 mac 或者 windows 上没有的库的话， 可以进行
(构建、执行、部署)->工具链->配置远程工具, 然后在 cmake 之中选择远程工
具，然后就会将远端的一些头文件库拉取下来，然后我们可以进行本地的开发。

2. 设置远程工具链之后, 会有一个默认的目录映射，最好开启一个全新的目录映射，
这样不会进行相互的影响。

# directory illustration:

1. src/
    1. api/ 一些 ftrace hook 相关的 api 以及 srv6 check 的相关 api。
    2. hooks/ 所有的对于内核函数的 hook 和 impl。
    3. prepare/ 是在 hook 之前的一些准备工作, 比如进行函数地址的解析。
    4. tools/ 一些工具, 比如进行带前缀的日志的输出
2. headers/ 存储的头文件

# version

1. version v1.0 github 上的第一个版本, 将 udp_sendmsg 内部函数全换成了代码, 
但是没有进行函数的内部的逻辑的修改。

# functions illustration

## app layer
- inet_sendmsg 是 tcp 和 udp 的上层函数

## transport layer
- udp_sendmsg 是 udp_sendmsg 的 implementation 和 hook
- udp_send_skb
- tcp_rcv_established
- tcp_v4_do_rcv
- tcp_v4_rcv

## network layer
- ip6_rc_finish_core 
- ip_append_data
- ip_make_skb
- ip_select_ident
- ip_send_skb
- ip_setup_cork
- ipv6_rcv
- ipv6_rcv_finish

## mac layer
- netif_rcv_skb 接口收包函数