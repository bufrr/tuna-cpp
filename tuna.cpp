//
// Created by yc chow on 2021/2/22.
//

#include "tuna.h"

tuna::tuna(boost::asio::io_context &io_context, const string &seed, shared_ptr<node_info> ni, bool *stop) :
        context_(io_context), socket_(io_context), ni_(std::move(ni)), stop_(stop) {
    auto acc = Wallet::Account::NewAccount(seed);                       // new Random account
    wallet_ = Wallet::NewWallet(acc, Wallet::WalletCfg::MergeWalletConfig(nullptr));
}

void tuna::async_choose_local(std::function<void(std::shared_ptr<nkn_Local>)> f) {
    auto i = rand() % conn_num;
    auto local = locals_[i].lock();
    if ((!local) || local->is_destroyed()) {
        local = std::make_shared<nkn_Local>(context_, wallet_, ni_, stop_);
        local->run();
        locals_[i] = local;
        f(local);
        return;
    }
    f(local);
}
