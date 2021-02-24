//
// Created by yc chow on 2021/2/20.
//

#ifndef EXIT_H
#define EXIT_H

#include "nkn_local.h"
#include "tuna.h"

class tuna_exit : virtual public tuna {
public:
    tuna_exit(boost::asio::io_context &io_context, tcp::endpoint to, const string &seed,
              shared_ptr<node_info> ni, bool *stop);

    ~tuna_exit();

    void run();

private:
    //void connect_handler(const boost::system::error_code &err);

private:
    tcp::socket socket_;
    tcp::endpoint to_;
};


#endif //EXIT_H
