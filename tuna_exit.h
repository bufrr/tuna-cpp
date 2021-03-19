//
// Created by yc chow on 2021/2/20.
//

#ifndef EXIT_H
#define EXIT_H

#include "nkn_local.h"
#include "tuna.h"

class tuna_exit : virtual public tuna {
public:
    tuna_exit(boost::asio::io_context &io_context, const string &seed, const string ip, const int port,
              shared_ptr<node_info> ni, bool *stop);

    ~tuna_exit();

    void run() override;

    void connect_local_service();

    void do_connect_loop();

private:
    //void connect_handler(const boost::system::error_code &err);

private:
    tcp::socket socket_;
    tcp::endpoint remote_ep_;
};


#endif //EXIT_H
