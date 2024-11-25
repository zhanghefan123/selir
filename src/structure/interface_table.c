#include "structure/interface_table.h"

/**
 * 进行接口表的初始化
 * @param number_of_interfaces
 * @return
 */
struct ArrayBasedInterfaceTable* initialize_array_based_interface_table(int number_of_interfaces){
    // 分配内存
    struct ArrayBasedInterfaceTable *ibrt = (struct ArrayBasedInterfaceTable*)kmalloc(sizeof(struct ArrayBasedInterfaceTable), GFP_KERNEL);
    // 设置接口数量
    ibrt->number_of_interfaces = number_of_interfaces;
    // 为接口表分配内存
    ibrt->interfaces = (struct InterfaceTableEntry*)kmalloc(sizeof(struct InterfaceTableEntry) * number_of_interfaces, GFP_KERNEL);
    // 进行创建结果返回
    return ibrt;
}

/**
 * 进行接口表的释放
 * @param abit
 */
void free_array_based_interface_table(struct ArrayBasedInterfaceTable* abit){
    if(NULL != abit){
        if(NULL != abit->interfaces){
            kfree(abit->interfaces);
        }
        kfree(abit);
        abit = NULL;
    }
}

/**
 * 利用链路标识进行接口表的查找
 * @param pvs
 * @param link_identifier
 * @return
 */
struct InterfaceTableEntry* find_intf_in_abit(struct ArrayBasedInterfaceTable* abit, int link_identifier){
    int index;
    struct InterfaceTableEntry* result = NULL;
    for(index = 0; index < abit->number_of_interfaces; index++){
        if(abit->interfaces[index].link_identifier == link_identifier){
            result = &(abit->interfaces[index]);
            break;
        }
    }
    return result;
}
