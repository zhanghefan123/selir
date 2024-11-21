#include "api/netlink_router.h"
#include "api/netlink_handler.h"
#include "structure/path_validation_structure.h"
#include "structure/namespace.h"

/**
 * 提取 netlink 消息
 * @param info generate netlink 消息
 * @return 解析得到的消息
 */
char *recv_message(struct genl_info *info) {
    // 1. 判断 generate netlink info 是否为 NULL
    if (NULL == info) {
        return "";
    }
    // 2. 判断是否存在数据
    if (!info->attrs[EXMPL_NLA_DATA]) {
        return "";
    }
    // 3. 进行消息的返回
    return nla_data(info->attrs[EXMPL_NLA_DATA]);
}

/**
 * 发送响应消息
 * @param response_buffer
 */
int send_reply(char *response_buffer, struct genl_info *info) {
    struct sk_buff *reply_message;       // 相应消息
    void *message_header;                // 消息头部
    // 1. 进行消息头的内存分配
    message_header = genlmsg_put_reply(reply_message, info, &exmpl_genl_family, 0, info->genlhdr->cmd);
    if (NULL == message_header) {
        return -ENOMEM;
    }
    // 2. 进行消息的内存分配
    reply_message = genlmsg_new(NLMSG_GOODSIZE, GFP_KERNEL);
    if (NULL == reply_message) {
        return -ENOMEM;
    }
    // 3. 填充 EXMPL_NLA_DATA 部分
    if (0 != nla_put_string(reply_message, EXMPL_NLA_DATA, response_buffer)) {
        return -EINVAL;
    }
    // 4. 填充 EXMPL_NLA_LEN 部分
    if (0 != nla_put_u32(reply_message, EXMPL_NLA_LEN, strlen(response_buffer))) {
        return -EINVAL;
    }
    // 5. 结束响应消息的构建
    genlmsg_end(reply_message, message_header);
    // 6. 进行消息的返回
    if (0 != genlmsg_reply(reply_message, info)) {
        return -EINVAL;
    }
    return 0;
}

/**
 * 处理回显命令
 * @param request
 * @param info
 * @return
 */
int netlink_echo_handler(struct sk_buff *request, struct genl_info *info) {
    // 1. 变量的定义
    // -----------------------------------------------------------------
    char *receive_buffer;                // 接收缓存 - 用来缓存用户空间下发的数据
    char response_buffer[1024];         // 响应消息缓存
    // -----------------------------------------------------------------

    // 2. 准备进行消息的处理
    // -----------------------------------------------------------------
    receive_buffer = recv_message(info);
    if (0 == strcmp("", receive_buffer)) {
        return -EINVAL;
    }
    snprintf(response_buffer, sizeof(response_buffer), "%s", receive_buffer);
    // -----------------------------------------------------------------

    // 3. 准备进行消息的返回
    // -----------------------------------------------------------------
    return send_reply(response_buffer, info);
    // -----------------------------------------------------------------
}

/**
 * 处理初始化命令
 * @param request
 * @param info
 * @return
 */
int netlink_init_routing_and_forwarding_table_handler(struct sk_buff *request, struct genl_info *info) {
    // 1. 变量的定义
    // -----------------------------------------------------------------
    char *receive_buffer;               // 接收缓存 - 用来缓存用户空间下发的数据
    char response_buffer[1024];         // 响应消息缓存
    const char *delimeter = ",";        // 分隔符
    int count = 0;                      // 表示当前是第几个属性
    struct net *current_ns = sock_net(request->sk);
    // -----------------------------------------------------------------

    // 2. 参数的定义
    // -----------------------------------------------------------------
    int number_of_routes;
    int number_of_interfaces;
    // -----------------------------------------------------------------

    // 3. 准备进行消息的处理
    // -----------------------------------------------------------------
    // 消息格式: number_of_routes, number_of_interfaces
    // 3.1 读取参数
    receive_buffer = recv_message(info);
    while (true) {
        // 分割出来的字符串
        char *variable_in_str = strsep(&receive_buffer, delimeter);
        // 如果为空就进行 break
        if (variable_in_str == NULL || (0 == strcmp(variable_in_str, ""))) {
            break;
        } else {
            int variable_in_integer = (int) (simple_strtol(variable_in_str, NULL, 10));
            if (count == 0) {
                number_of_routes = variable_in_integer;
            } else if (count == 1) {
                number_of_interfaces = variable_in_integer;
            } else {
                return -EINVAL;
            }
        }
        count += 1;
    }
    // 3.2 创建 path validation structure
    struct PathValidationStructure *path_validation_structure = initialize_path_validation_structure(number_of_routes,
                                                                                                     number_of_interfaces);
    // 3.3 设置到 namespace 之中
    set_pvs_in_ns(current_ns, path_validation_structure);
    // -----------------------------------------------------------------

    // 4. 准备进行消息的返回
    // -----------------------------------------------------------------
    snprintf(response_buffer, sizeof(response_buffer), "number_of_routes: %d, number_of_interfaces: %d",
             number_of_routes, number_of_interfaces);
    return send_reply(response_buffer, info);
    // -----------------------------------------------------------------
}

/**
 * 处理初始化命令
 * @param request
 * @param info
 * @return
 */
int netlink_init_bloom_filter_handler(struct sk_buff *request, struct genl_info *info) {
    // 1. 变量的定义
    // -----------------------------------------------------------------
    char *receive_buffer;               // 接收缓存 - 用来缓存用户空间下发的数据
    char response_buffer[1024];         // 响应消息缓存
    const char *delimeter = ",";        // 分隔符
    int count = 0;                      // 表示当前是第几个属性
    struct net *current_ns = sock_net(request->sk);
    // -----------------------------------------------------------------

    // 2. 参数的定义
    // -----------------------------------------------------------------
    int total_length; // 单位为 8 字节 (底层的大小)
    int effective_bits; // 单位为 bit (实际的使用的位数)
    int hash_seed; // 哈希种子
    int number_of_hash_functions; // 哈希函数的个数
    // -----------------------------------------------------------------

    // 3. 准备进行消息的处理
    // -----------------------------------------------------------------
    // 消息格式: total_length, effective_bits, hash_seed, number_of_hash_functions
    // 3.1 读取参数
    receive_buffer = recv_message(info);
    while (true) {
        // 分割出来的字符串
        char *variable_in_str = strsep(&receive_buffer, delimeter);
        // 如果为空就进行 break
        if (variable_in_str == NULL || (0 == strcmp(variable_in_str, ""))) {
            break;
        } else {
            int variable_in_integer = (int) (simple_strtol(variable_in_str, NULL, 10));
            if (count == 0) {
                total_length = variable_in_integer;
            } else if (count == 1) {
                effective_bits = variable_in_integer;
            } else if (count == 2) {
                hash_seed = variable_in_integer;
            } else if (count == 3) {
                number_of_hash_functions = variable_in_integer;
            } else {
                return -EINVAL;
            }
        }
        count += 1;
    }
    // 3.2 创建 bloom filter
    struct BloomFilter *bloom_filter = init_bloom_filter(total_length,
                                                         effective_bits,
                                                         hash_seed,
                                                         number_of_hash_functions);
    // 3.3 设置到 namespace 之中
    struct PathValidationStructure *pvs = get_pvs_from_ns(current_ns);
    if (NULL == pvs) {
        return -EINVAL;
    } else {
        pvs->bloom_filter = bloom_filter;
    }
    // -----------------------------------------------------------------

    // 4. 准备进行消息的返回
    // -----------------------------------------------------------------
    snprintf(response_buffer, sizeof(response_buffer),
             "total_length: %d, effective_bits: %d, hash_seed: %d, number_of_hash_functions: %d",
             total_length, effective_bits, hash_seed, number_of_hash_functions);
    return send_reply(response_buffer, info);
    // -----------------------------------------------------------------
}

