//
// Created by yc chow on 2021/2/20.
//

#include "tuna_exit.h"

#include <utility>

tuna_exit::tuna_exit(boost::asio::io_context &io_context, const string &seed, const string ip, const int port,
                     shared_ptr<node_info> ni, bool *stop)
        : tuna(io_context, seed, std::move(ni),
               stop), socket_(io_context) {
    auto acc = Wallet::Account::NewAccount(seed);
    wallet_ = Wallet::NewWallet(acc, Wallet::WalletCfg::MergeWalletConfig(nullptr));
    remote_ep_ = tcp::endpoint(boost::asio::ip::address::from_string(ni_->ip), ni_->port);
    //socket_.connect(tcp::endpoint(ip), port);
}

tuna_exit::~tuna_exit() {
}

void tuna_exit::run() {
    cout << "run" << endl;
    auto self = shared_from_this();
    locals_.reserve(conn_num);
    for (int i = 0; i < conn_num; i++) {
        auto l = std::make_shared<nkn_Local>(context_, wallet_, ni_, stop_);
        l->run();
        locals_.emplace_back(l);
    }
    do_connect_loop();
}

void tuna_exit::connect_local_service() {
    auto self = shared_from_this();
    socket_.connect(remote_ep_);
    auto s = make_shared<tcp::socket>(std::move(socket_));
    async_choose_local([this, self, s](std::shared_ptr<nkn_Local> local) {
        if (!local) {
            return;
        }
        local->async_connect([this, self, s](std::shared_ptr<smux_sess> sess) {
            if (!sess) {
                return;
            }
            std::make_shared<nkn_client_session>(s, sess)->run_exit_reverse(ni_->service_id);
        });
    });
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
            local->send_service_metadata(9999);
            local->receive_service_metadata(9999);
            local->connect_service("127.0.0.1", 2015);
            local->connected = true;
            //std::this_thread::sleep_for(std::chrono::milliseconds(3000)); // sleep for 1 second
        });
    });

}

