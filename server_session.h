//
// Created by yc chow on 2021/3/11.
//

#ifndef TUNA_SERVER_SESSION_H
#define TUNA_SERVER_SESSION_H

#include "smux-cpp/client_session.h"
#include "pb/tuna.pb.h"

class smux_sess;

using boost::asio::ip::tcp;

class server_session : public std::enable_shared_from_this<server_session>, public Destroy, public kvar_ {
public:
    server_session(boost::asio::io_context &io_context, std::shared_ptr<smux_sess> sess,
                   tcp::endpoint local_endpoint);

    void run();

protected:
    void do_pipe1();

    void do_pipe2();

    void call_this_on_destroy() override;

protected:
    char buf1_[4096]{};
    char buf2_[4096]{};
    boost::asio::io_context &context_;
    tcp::endpoint local_endpoint_;
    std::unordered_map<uint16_t , std::weak_ptr<tcp::endpoint>> endpoints_;
    tcp::socket sock_;

protected:
    std::shared_ptr<smux_sess> sess_;
};

#endif //TUNA_SERVER_SESSION_H
