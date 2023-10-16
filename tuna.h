//
// Created by yc chow on 2021/2/20.
//

#ifndef TUNA_H
#define TUNA_H

#include <utility>

#include "nkn_local.h"

using boost::asio::ip::tcp;

static const int conn_num = 1;

class tuna : public std::enable_shared_from_this<tuna>, public Destroy {
public:
    tuna(boost::asio::io_context &io_context, const string &seed, vector<shared_ptr<node_info>> nis, bool *stop);

    ~tuna() = default;

    virtual void run() = 0;

    bool *stop_;

protected:
    void async_choose_local(std::function<void(std::shared_ptr<nkn_Local>)> f);


protected:
    boost::asio::io_service &context_;
    tcp::socket socket_;
    std::vector<std::weak_ptr<nkn_Local>> locals_;
    shared_ptr<Wallet::Wallet> wallet_;
    vector<shared_ptr<node_info>> nis_;
    uint nis_index_{};
    //shared_ptr<node_info> ni_;

    //tcp::endpoint from_endpoint_;
    //tcp::endpoint to_endpoint_;
    //tcp::acceptor acceptor_;
};

#endif //TUNA_H
