//
// Created by yc chow on 2021/2/20.
//

#include "tuna_exit.h"

#include <utility>

tuna_exit::tuna_exit(boost::asio::io_context &io_context, const string &seed, const string local_ip,
                     const int local_port, vector<shared_ptr<node_info>> nis,bool *stop, tcp::socket socket)
        : tuna(io_context, seed, nis, stop), local_ip_(local_ip), local_port_(local_port) {
    auto acc = Wallet::Account::NewAccount(seed);
    wallet_ = Wallet::NewWallet(acc, Wallet::WalletCfg::MergeWalletConfig(nullptr));
//    remote_ep_ = tcp::endpoint(boost::asio::ip::address::from_string(ni_->ip), ni_->port);
//    local_ep_ = tcp::endpoint(boost::asio::ip::address::from_string(local_ip), local_port);
    //socket_.connect(tcp::endpoint(ip), port);
}

tuna_exit::~tuna_exit() {
}

void tuna_exit::run() {
    auto self = shared_from_this();
    locals_.reserve(conn_num);
    for (int i = 0; i < conn_num; i++) {
        auto l = std::make_shared<nkn_Local>(context_, wallet_, nis_[i], stop_);
        l->run();
        locals_.emplace_back(l);
    }
    do_connect_loop();
}


void tuna_exit::do_connect_loop() {
    auto self = shared_from_this();
    auto stat_timer = std::make_shared<boost::asio::high_resolution_timer>(
            context_, std::chrono::seconds(1));
    stat_timer->async_wait([this, self, stat_timer](const std::error_code &) {
        async_choose_local([this, self](std::shared_ptr<nkn_Local> local) {
            if (!local || local->connected) {
                do_connect_loop();
            }
            local->send_service_metadata();
            local->receive_service_metadata();
            local->connect_local_service(local_ip_, local_port_);
            local->connected = true;
            //std::this_thread::sleep_for(std::chrono::milliseconds(3000)); // sleep for 1 second
        });
    });

}

