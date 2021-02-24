//
// Created by yc chow on 2020/11/23.
//

#include "entry.h"

#include <utility>

entry::entry(boost::asio::io_context &io_context,
             const tcp::endpoint &from,
             const string &seed, shared_ptr<node_info> ni, bool *stop) : tuna(io_context, seed, std::move(ni), stop),
                                                                         acceptor_(io_context, from) {
}

entry::~entry() {
    std::cout << "entry closed! " << std::endl;
}

void entry::run() {
    locals_.reserve(conn_num);
    for (int i = 0; i < conn_num; i++) {
        auto l = std::make_shared<nkn_Local>(context_, wallet_, ni_, stop_);
        l->run();
        locals_.emplace_back(l);
    }
    acceptor_.set_option(tcp::acceptor::reuse_address(true));
    do_accept();
}

void entry::do_accept() {
    auto self = shared_from_this();
    acceptor_.async_accept(socket_, [this, self](std::error_code ec) {
        if (ec) {
            return;
        }
        auto sock = std::make_shared<tcp::socket>(std::move(socket_));
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
        do_accept();
    });
}
