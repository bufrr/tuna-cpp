//
// Created by yc chow on 2020/11/23.
//

#ifndef TEST_ENTRY_H
#define TEST_ENTRY_H

#include "nkn_local.h"

class entry final : public std::enable_shared_from_this<entry>, public Destroy {
public:
    entry(boost::asio::io_context &io_context, const tcp::endpoint &from, const string seed,
          shared_ptr<node_info> ni, bool *stop);

    ~entry();

    void run();

    bool *stop_;

private:
    void do_accept();

    void async_choose_local(std::function<void(std::shared_ptr<nkn_Local>)> f);


private:
    boost::asio::io_service &context_;
    tcp::socket socket_;
    tcp::endpoint from_endpoint_;
    //tcp::endpoint to_endpoint_;
    tcp::acceptor acceptor_;
    std::vector<std::weak_ptr<nkn_Local>> locals_;
    shared_ptr<Wallet::Wallet> wallet_;
    shared_ptr<node_info> ni_;
};

#endif //TEST_ENTRY_H
