#include <automata_handler.h>
#include <algorithm>
#include <stack>
#include <vector>
 
std::set<std::string> ltlfuzz::ALL_EVENTS;


ltlfuzz::AutomataHandler::AutomataHandler(lfz::automata::Automata* atm){
    this->atm = atm;
}

void ltlfuzz::load_ALL_EVENTS(std::string fileName){
    std::ifstream fileReader(fileName);
    std::cout << "filename is: " << fileName << std::endl;
    if(!fileReader.is_open()) throw std::runtime_error("could not open the event_file at Load_all_events");
    std::cout << "------------Loding ALL Events--------- " << std::endl;
    std::string line;
    while(std::getline(fileReader, line)){
        std::stringstream input(line);
        std::string result;
        input >> result;
        std::cout << "event: " << result << std::endl;
        ltlfuzz::ALL_EVENTS.insert(result);
    }
    std::cout << "-----------------loading Done: " << ALL_EVENTS.size() << "--------------" << std::endl;
    fileReader.close();
}

std::vector<std::string> ltlfuzz::AutomataHandler::path_ahead(std::string curState){
    std::vector<std::string> seq;
    lfz::automata::paths_t paths;
    // 论文 get_state_paths 的 aPath = 已访问状态表（函数内往 10 元素
    // isVisited 逐个写 aPath.size() 个标记——传大向量会越界，2026-10-04
    // ASAN 实测）。此处无历史路径，传空表 = 不预标记。
    std::vector<int> visited;
    try {
        this->atm->get_state_paths(std::stoi(curState), paths, visited);
    } catch (...) {
        return seq;
    }
    if (paths.empty()) return seq;
    std::stack<int> st = paths.front();
    std::vector<int> states;
    while (!st.empty()) { states.push_back(st.top()); st.pop(); }
    std::reverse(states.begin(), states.end());
    for (size_t i = 0; i + 1 < states.size(); ++i) {
        lfz::automata::events_t evs;
        this->atm->get_state_events(states[i], states[i + 1], evs);
        std::set<std::string> pos;
        for (auto& s : evs)
            for (auto& e : s)
                if (!e.empty() && e.front() != '!')
                    pos.insert(e);
        if (pos.empty()) continue;
        std::string step;
        for (auto& e : pos) {
            if (!step.empty()) step += "|";
            step += e;
        }
        seq.push_back(step);
    }
    return seq;
}

std::string ltlfuzz::AutomataHandler::select_event(std::string curState, std::string aPath){
    ltlfuzz::AutomataTransition tran = select_tran(curState, aPath);
    ltlfuzz::Proposition prop = select_proposition(tran);
    ltlfuzz::EventSet eSet = extract_proposition_events(prop);
    return select_event(eSet);
}

ltlfuzz::AutomataTransition ltlfuzz::AutomataHandler::select_tran(std::string curState, std::string aPath){
    std::set<int> sPath;
    std::vector<std::string> vPath;
    aPath = aPath.substr(0, aPath.size()-1);
    boost::split(vPath, aPath, [](char c){return c == ',';});
    for(auto& e : vPath){
        sPath.insert(std::stoi(e));
    }

    for(auto&e : sPath){
        std::cout << ">>> test existing path: " << e << std::endl;
    }
    
    int state = std::stoi(curState);
    lfz::automata::transitions_t trans;

    this->atm->get_state_transitions(state, trans);


    std::cout << "debug: " << curState << std::endl;
    std::vector<std::pair<std::any, double>> vector_;

    for(auto& e : trans){
        std::set<int>::iterator it;
        it = sPath.find(e.second);
        std::cout << "next state: " << e.second << std::endl;
        if(it == sPath.end()){
            ltlfuzz::AutomataTransition tran(e.first, std::to_string(e.second));
            vector_.push_back(std::make_pair(tran,1.0));
        }
    }

    if(vector_.size() == 0){
        for(auto& e : trans){
            ltlfuzz::AutomataTransition tran(e.first, std::to_string(e.second));
            vector_.push_back(std::make_pair(tran,1.0));
        }
    }

    std::any selected = strategy::RandomStrategy::instance()->select(vector_);
    ltlfuzz::AutomataTransition trans_selected = std::any_cast<ltlfuzz::AutomataTransition> (selected);


    std::cout << "Selected transition: "<< std::endl;
    trans_selected.dump();

    return trans_selected;


}

ltlfuzz::Proposition ltlfuzz::AutomataHandler::select_proposition(ltlfuzz::AutomataTransition tran){
    std::vector<std::pair<std::any, double>> vector_;

    for(auto& e : tran.propositions){
        ltlfuzz::Proposition prop(e);
        vector_.push_back(std::make_pair(prop,1.0));
    }

    std::any selected = strategy::RandomStrategy::instance()->select(vector_);
    ltlfuzz::Proposition prop = std::any_cast<ltlfuzz::Proposition> (selected);

    return prop;
}

ltlfuzz::EventSet ltlfuzz::AutomataHandler::extract_proposition_events(ltlfuzz::Proposition prop){
    std::set<std::string> eSet;
    for(auto e : prop.events){

        if(e.front() == '!'){
            eSet.insert(e.erase(0));
        }
        else{
            eSet.clear();
            eSet.insert(e);
            return ltlfuzz::EventSet(eSet, ltlfuzz::EventType::ACCEPT);
        }

    }
    return ltlfuzz::EventSet(eSet, ltlfuzz::EventType::REJECT);
}

std::string ltlfuzz::AutomataHandler::select_event(ltlfuzz::EventSet eSet){

     std::vector<std::pair<std::any, double>> vector_;

     switch (eSet.eventType){
         case ltlfuzz::EventType::ACCEPT :
             for( auto& e : eSet.events ){
                 vector_.push_back(std::make_pair(e, 1.0));
             }
             break;

         case ltlfuzz::EventType::REJECT :
             std::set<std::string> accept_events;
             std::set_difference(ltlfuzz::ALL_EVENTS.begin(), ltlfuzz::ALL_EVENTS.end(), eSet.events.begin(), eSet.events.end(), std::inserter(accept_events, accept_events.end()));

             for(auto& e : accept_events){
                 vector_.push_back(std::make_pair(e, 1.0));
             }
             break;
     }

     std::any selected = strategy::RandomStrategy::instance()->select(vector_);
     std::string event = std::any_cast<std::string> (selected);

     return event;
}

// 从 curState 走到接受态，读接受态自环标签生成见证规格：
// 正字面量 = 可停留事件（liveness 重复的对象），取反字面量 = 禁止事件。
ltlfuzz::WitnessSpec ltlfuzz::AutomataHandler::witness_spec(std::string curState){
    WitnessSpec spec;
    int cur;
    try {
        cur = std::stoi(curState);
    } catch (...) {
        return spec;
    }
    // 当前态自身即接受（get_state_paths 只查后继、get_state_set 跳过
    // 自环，自身接受时返回空——2026-10-05 表征 bug 根因），优先取自身；
    // 否则走路径到最近接受态。
    int acc = -1;
    if (this->atm->is_state_accepting(cur)) {
        acc = cur;
    } else {
        lfz::automata::paths_t paths;
        std::vector<int> visited;  // 论文 get_state_paths：aPath=已访问状态表
        try {
            this->atm->get_state_paths(cur, paths, visited);
        } catch (...) {
            return spec;
        }
        if (paths.empty()) return spec;
        std::stack<int> st = paths.front();
        std::vector<int> states;
        while (!st.empty()) { states.push_back(st.top()); st.pop(); }
        std::reverse(states.begin(), states.end());
        if (states.empty()) return spec;
        acc = states.back();                     // 路径终点 = 接受态
    }
    lfz::automata::events_t evs;
    this->atm->get_state_events(acc, acc, evs);  // 自环标签
    for (auto& eset : evs) {
        for (auto& e : eset) {
            if (e.size() > 1 && e.front() == '!') {
                std::string neg = e.substr(1);
                if (std::find(spec.forbidden.begin(), spec.forbidden.end(), neg)
                        == spec.forbidden.end())
                    spec.forbidden.push_back(neg);
            } else if (!e.empty() &&
                       std::find(spec.loop_events.begin(),
                                 spec.loop_events.end(), e)
                           == spec.loop_events.end()) {
                spec.loop_events.push_back(e);
            }
        }
    }
    spec.has_loop = !evs.empty();
    return spec;
}
