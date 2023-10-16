//
// Created by yc chow on 2020/11/23.
//

#include "entry.h"

#include <utility>

entry::entry(boost::asio::io_context &io_context,
             const tcp::endpoint &from,
             const string &seed, vector<shared_ptr<node_info>> nis, bool *stop) : tuna(io_context, seed, nis, stop),
                                                                                  acceptor_(io_context, from) {
}

entry::~entry() {
    std::cout << "entry closed! " << std::endl;
}

void entry::run() {
    locals_.reserve(conn_num);

    while (true) {
        auto ni = nis_[nis_index_ % nis_.size()];
        nis_index_++;
        auto l = std::make_shared<nkn_Local>(context_, wallet_, ni, stop_);
        if (l->connected) {
            l->run();
            l->send_payment();
            locals_.emplace_back(l);

            acceptor_.set_option(tcp::acceptor::reuse_address(true));
            do_accept();
            break;
        }
    }
}

void entry::do_accept() {
    auto self = shared_from_this();
    acceptor_.async_accept(socket_, [this, self](std::error_code ec) {
        TRACE
        if (ec) {
            TRACE
            return;
        }
        auto sock = std::make_shared<tcp::socket>(std::move(socket_));
        async_choose_local([this, self, sock](std::shared_ptr<nkn_Local> local) {
            if (!local) {
                cerr << "accept but no local" << endl;
                sock->close();
                return;
            }
            local->async_connect([this, self, sock, local](std::shared_ptr<smux_sess> sess) {
                if (!sess) {
                    cerr << "sess is nullptr" << endl;
                    sock->close();
                    return;
                }
                std::make_shared<nkn_client_session>(sock, sess)->run(local->get_service_id());
                TRACE
            });
        });
        do_accept();
    });
}
