//
// Created by yc chow on 2021/2/20.
//

#include "tuna_exit.h"

#include <utility>

tuna_exit::tuna_exit(boost::asio::io_context &io_context, tcp::endpoint to,
                     const string &seed, shared_ptr<node_info> ni, bool *stop) : tuna(io_context, seed, std::move(ni),
                                                                                      stop), socket_(io_context),
                                                                                 to_(std::move(to)) {
    auto acc = Wallet::Account::NewAccount(seed);
    wallet_ = Wallet::NewWallet(acc, Wallet::WalletCfg::MergeWalletConfig(nullptr));
}

tuna_exit::~tuna_exit() {
}

void tuna_exit::run() {
    auto self = shared_from_this();
    locals_.reserve(conn_num);
    for (int i = 0; i < conn_num; i++) {
        auto l = std::make_shared<nkn_Local>(context_, wallet_, ni_, stop_);
        l->run();
        locals_.emplace_back(l);
    }
    socket_.async_connect(to_, [this, self](const boost::system::error_code &ec) {
        auto sock = std::make_shared<tcp::socket>(std::move(socket_));
        if (ec) {
            cout << "async_connect err:" << ec.message() << endl;
            return;
        }
        async_choose_local([this, self, sock](std::shared_ptr<nkn_Local> local) {
            if (!local) {
                return;
            }
            local->async_connect([this, self, sock](std::shared_ptr<smux_sess> sess) {
                if (!sess) {
                    return;
                }
                std::make_shared<nkn_client_session>(sock, sess)->run(ni_->service_id);
            });
        });
    });
}

