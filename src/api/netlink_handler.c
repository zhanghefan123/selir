#include "api/netlink_router.h"-
#include "api/netlink_handler.h"

int netlink_test_handler(struct sk_buff* request, struct genl_info* info){
    // 1. 变量的定义
    // -----------------------------------------------------------------
    struct sk_buff* reply_message;       // 相应消息
    char* receive_buffer;                // 接收缓存 - 用来缓存用户空间下发的数据
    void* message_header;                // 消息头部
    char response_buffer[1024];         // 响应消息缓存
    // -----------------------------------------------------------------

    // 2. 进行预先的校验
    // -----------------------------------------------------------------
    // 2.1 判断 generic netlink info 是否为 NULL
    if(NULL == info){
        return -EINVAL;
    }
    // 2.2 判断是否存在数据
    if(!info->attrs[EXMPL_NLA_DATA]){
        return -EINVAL;
    }
    // -----------------------------------------------------------------

    // 3. 准备进行消息的处理
    // -----------------------------------------------------------------
    receive_buffer = nla_data(info->attrs[EXMPL_NLA_DATA]);
    // -----------------------------------------------------------------

    // 4. 准备进行消息的返回
    // -----------------------------------------------------------------
    // 4.1 进行消息的内存分配
    reply_message = genlmsg_new(NLMSG_GOODSIZE, GFP_KERNEL);
    if(NULL == reply_message){
        return -ENOMEM;
    }
    // 4.2 进行消息头的内存分配
    message_header = genlmsg_put_reply(reply_message, info, &exmpl_genl_family, 0, info->genlhdr->cmd);
    if(NULL == message_header){
        return -ENOMEM;
    }
    // 4.3 填充响应消息
    snprintf(response_buffer, sizeof(response_buffer), "%s", receive_buffer);
    // 4.4 进行响应消息的构建
    // 4.4.1 填充 EXMPL_NLA_DATA 部分
    if (0 != nla_put_string(reply_message, EXMPL_NLA_DATA, response_buffer)) {
        return -EINVAL;
    }
    // 4.4.2 填充 EXMPL_NLA_LEN 部分
    if (0 != nla_put_u32(reply_message, EXMPL_NLA_LEN, strlen(response_buffer))) {
        return -EINVAL;
    }
    // 4.5 结束响应消息的构建
    genlmsg_end(reply_message, message_header);
    // 4.6 进行消息的返回
    if(0 != genlmsg_reply(reply_message, info)) {
        return -EINVAL;
    }
    return 0;
    // -----------------------------------------------------------------
}