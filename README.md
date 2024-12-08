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

3. path_validation_structure 之中包含了 array_based_routing_table 而 array_based_routing_table 之中又包含 path_validation_structure 
这是绝对不被允许的。这就是循环引用。就可能出现 Incompatiable Type 的情况。

4. 当 skb_copy 的时候并不会进行 skb->sk 的拷贝, 还有以后不要尝试从通过 udp_sendmsg 向多个地方进行发包了, 试过很多次了

5. 原先在 free_pvs 之中进行了 free_crypto_api, 现在已经注释掉了，因为如果不注释，多次 insmod rmmod 之后会报错

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
2. version v2.0 github 上实现了基本的 lir。