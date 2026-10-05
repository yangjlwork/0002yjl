#include <iostream>
#include <automata.h>
#include <automata_transition.h>
#include <event.h>
#include <random_strategy.h>
#include <proposition.h>
#include <string>
#include <sstream>
#include <fstream>
#include <boost/algorithm/string.hpp>

#ifndef AUTOMATA_HANDLER_H
#define AUTOMATA_HANDLER_H

namespace ltlfuzz{
    extern std::set<std::string> ALL_EVENTS; //all exclusive events
	extern void load_ALL_EVENTS(std::string fileName);

    // 见证规格：由 ¬φ 自动机结构自动推导（无人工指定的事件名）。
    // loop_events = 接受态自环标签中的正事件（可重复触发以停留）；
    // forbidden   = 自环标签中取反的事件（出现即毁掉 G¬… 见证）。
    struct WitnessSpec {
        bool has_loop = false;
        std::vector<std::string> loop_events;
        std::vector<std::string> forbidden;
    };

    class AutomataHandler{
        public:
            AutomataHandler(lfz::automata::Automata* atm);
            std::string select_event(std::string curState, std::string aPath);

    // 给求解引擎的引导信号：从 curState 到最近接受态的事件序列
    // （automata.cc get_state_paths/find_paths 的封装）。论文的对应
    // 引导是 AFLGo 的 CFG 距离——信息来源同为自动机，形态不同。
    std::vector<std::string> path_ahead(std::string curState);
    WitnessSpec witness_spec(std::string curState);
            
        private:
            lfz::automata::Automata* atm;
            
            AutomataTransition select_tran(std::string curState, std::string aPath);
            Proposition select_proposition(AutomataTransition tran);
            EventSet extract_proposition_events(Proposition prop);
            std::string select_event(EventSet eSet);

    };
}

#endif 

