#include "shared_table.h"
#include <string.h>
#include <stdlib.h>
#include "pathwriter.h"

using std::cout;
using std::endl;
using namespace boost::interprocess;

inst::PathWriter::PathWriter(){}
inst::PathWriter::~PathWriter(){}

/* 论文原实现：全局对象启动即 open_only 打开共享段——协议模式
 * （驱动不建段）进程直接崩溃。改为惰性打开（RERS 模式由驱动先建段；
 * 打不开时如实报告并跳过写池）。 */
static managed_shared_memory* segment_w_ptr = nullptr;
static managed_shared_memory* get_segment_w() {
    if (!segment_w_ptr) {
        try {
            segment_w_ptr = new managed_shared_memory(open_only, shmId.c_str());
        } catch (boost::interprocess::interprocess_exception& e) {
            std::cout << "PathWriter: shared table 不存在（协议模式/独立运行）"
                      << "，跳过前缀池写回: " << e.what() << std::endl;
            return nullptr;
        }
    }
    return segment_w_ptr;
}

void inst::PathWriter::write_to_shared_table(std::string automata_path, std::string prefix, std::string metric){
    managed_shared_memory* seg = get_segment_w();
    if (seg == nullptr) return;
    void_allocator alloc_inst_w(seg->get_segment_manager());

    //get the shared table
    string_string_string_map *table = seg->find<string_string_string_map>(tableName.c_str()).first;

    //create char_string
    char_string path_automata_s(automata_path.c_str(), alloc_inst_w);
    char_string prefix_s(prefix.c_str(), alloc_inst_w);
    char_string metric_s(metric.c_str(), alloc_inst_w);
    
        
    if(table==nullptr)
        std::cout<<"failed to find the shared table" << std::endl;

    //insert into the map
    string_string_string_map::iterator sss_ite = table->find(path_automata_s);
    
    if(sss_ite == table->end()){

        string_string_value_type  ss_map_value(prefix_s, metric_s);
        string_string_map *col_map = seg->construct<string_string_map>
        ((automata_path+prefix).c_str())(std::less<char_string>(), alloc_inst_w);
        col_map->insert(ss_map_value);

        string_string_string_value_type sss_map_value(path_automata_s, *col_map);
        table->insert(sss_map_value);
    }
    else{
        sss_ite->second.insert(string_string_value_type(prefix_s, metric_s));
    }
}




