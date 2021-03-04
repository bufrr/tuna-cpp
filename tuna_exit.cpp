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
    remote_ep_ = tcp::endpoint(boost::asio::ip::address::from_string(ni->ip), ni->port);
    //socket_.connect(tcp::endpoint(ip), port);
    cout << 123 << endl;
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
//    socket_.async_connect(remote_ep_, [this, self](const boost::system::error_code &ec) {
//        auto sock = std::make_shared<tcp::socket>(std::move(socket_));
//        if (ec) {
//            cout << "async_connect err:" << ec.message() << endl;
//            return;
//        }
//        async_choose_local([this, self, sock](std::shared_ptr<nkn_Local> local) {
//            if (!local) {
//                return;
//            }
//            local->async_connect([this, self, sock](std::shared_ptr<smux_sess> sess) {
//                if (!sess) {
//                    return;
//                }
//                std::make_shared<nkn_client_session>(sock, sess)->run_exit_reverse(ni_->service_id);
//            });
//        });
//    });
}

