//
// Created by yc chow on 2021/2/22.
//

#include "tuna.h"

tuna::tuna(boost::asio::io_context &io_context, const string &seed, vector<shared_ptr<node_info>> nis, bool *stop) :
        context_(io_context), socket_(io_context), nis_(nis), stop_(stop) {
    auto acc = Wallet::Account::NewAccount(seed);                       // new Random account
    wallet_ = Wallet::NewWallet(acc, Wallet::WalletCfg::MergeWalletConfig(nullptr));
}

void tuna::async_choose_local(std::function<void(std::shared_ptr<nkn_Local>)> f) {
    auto i = rand() % conn_num;
    auto local = locals_[i].lock();
    if ((!local) || local->is_destroyed()) {
        auto ni = nis_[nis_index_ % nis_.size()];
        nis_index_++;
        local = std::make_shared<nkn_Local>(context_, wallet_, ni, stop_);
        local->run();
        local->send_payment();
        locals_[i] = local;
        f(local);
        return;
    }
    f(local);
}
