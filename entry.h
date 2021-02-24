//
// Created by yc chow on 2020/11/23.
//

#ifndef ENTRY_H
#define ENTRY_H

#include "nkn_local.h"
#include "tuna.h"

class entry : virtual public tuna {
public:
    entry(boost::asio::io_context &io_context, const tcp::endpoint &from, const string &seed,
          shared_ptr<node_info> ni, bool *stop);

    ~entry();

    void run();

private:
    void do_accept();

    //void async_choose_local(std::function<void(std::shared_ptr<nkn_Local>)> f);


private:
    //boost::asio::io_service &context_;
    //tcp::socket socket_;
    //tcp::endpoint from_endpoint_;
    //tcp::endpoint to_endpoint_;
    tcp::acceptor acceptor_;
//    std::vector<std::weak_ptr<nkn_Local>> locals_;
//    shared_ptr<Wallet::Wallet> wallet_;
//    shared_ptr<node_info> ni_;
};

#endif //ENTRY_H
