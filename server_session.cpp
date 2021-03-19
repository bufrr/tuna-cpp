//
// Created by yc chow on 2021/3/11.
//

#include "server_session.h"

#include <utility>

static kvar session_kvar("server_session");

server_session::server_session(boost::asio::io_context &io_context, std::shared_ptr<smux_sess> sess,
                               tcp::endpoint local_endpoint) : context_(io_context), sess_(std::move(sess)),
                                                               sock_(io_context),
                                                               local_endpoint_(std::move(local_endpoint)),
                                                               kvar_(session_kvar) {

}

void server_session::run() {
    auto self = shared_from_this();
    sock_.async_connect(local_endpoint_, [this, self](std::error_code ec) {
        if (ec) {
            std::cout << ec.message() << std::endl;
            return;
        }
        sess_->async_read_some(buf1_, 4, [this, self](std::error_code ec, std::size_t len) {
            do_pipe1();
            do_pipe2();
        });
    });
}

void server_session::do_pipe1() {
    auto self = shared_from_this();
    sock_.async_read_some(
            boost::asio::buffer(buf1_, sizeof(buf1_)),
            [this, self](std::error_code ec, std::size_t len) {
                if (ec) {
                    std::cout << "pipe1:" << ec.message() << std::endl;
                    destroy();
                    return;
                }
                sess_->async_write(
                        buf1_, len, [this, self](std::error_code ec, std::size_t len) {
                            if (ec) {
                                std::cout << "pipe11:" << ec.message() << std::endl;
                                destroy();
                                return;
                            }
                            do_pipe1();
                        });
            });
}


void server_session::do_pipe2() {
    auto self = shared_from_this();
    sess_->async_read_some(buf2_, sizeof(buf2_), [this,
            self](std::error_code ec,
                  std::size_t len) {
        if (ec) {
            std::cout << "pipe2:" << ec.message() << std::endl;
            destroy();
            return;
        }
        boost::asio::async_write(sock_, boost::asio::buffer(buf2_, len),
                                 [this, self](std::error_code ec, std::size_t len) {
                                     if (ec) {
                                         std::cout << "pipe22:" << ec.message() << std::endl;
                                         destroy();
                                         return;
                                     }
                                     do_pipe2();
                                 });
    });
}

void server_session::call_this_on_destroy() {
    auto self = shared_from_this();

    Destroy::call_this_on_destroy();

    sock_.close();
    if (sess_) {
        sess_->destroy();
    }
}