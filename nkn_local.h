//
// Created by yc chow on 2021/2/7.
//

#ifndef NKN_LOCAL_H
#define NKN_LOCAL_H

#include <sodium.h>
#include <boost/atomic.hpp>

#include "smux-cpp/local.h"
#include "smux-cpp/encrypt.h"
#include "smux-cpp/smux.h"
#include "smux-cpp/client_session.h"
#include "include/crypto/ed25519.h"
#include "include/rpc.h"
#include "include/wallet.h"

#include "nkn.h"
#include "nkn_client_session.h"
#include "server_session.h"
#include "pb/tuna.pb.h"


using boost::asio::ip::tcp;
using namespace NKN;

struct node_info;

class nkn_Local : public Local {
public:
    nkn_Local(boost::asio::io_context &io_context, shared_ptr<Wallet::Wallet> w, shared_ptr<node_info> ni, bool *stop);

    void run() override;

    void async_connect(std::function<void(std::shared_ptr<smux_sess>)> handler) override;

    void negotiate_conn_metadata(std::shared_ptr<tcp::socket> sock, pb::ConnectionMetadata md);

    void send_payment(uint32_t sid);

    void payment_checker(uint32_t sid);

    void send_service_metadata(uint32_t sid);

    void receive_service_metadata(uint32_t sid);

    void connect_service(string ip, int port);

//    uint32_t read_var_bytes(std::shared_ptr<tcp::socket> s, char *buf);
//
//    static void write_var_bytes(std::shared_ptr<tcp::socket> s, char *buf, std::size_t len);

    bool connected;

private:
    void do_sess_receive() override;

private:
    atomic_int64_t total_in_bytes_;
    atomic_int64_t total_out_bytes_;
    atomic_int64_t paid_bytes_;
    boost::posix_time::ptime last_payment_;

    char recv_msg_[65535]{};
    char send_msg_[65536]{};
    char plain_[65536]{};
    char nanopay_buf_[256]{};
    char stream_metadata_buf_[128];
    char service_metadata_buf_[4096];


    shared_ptr<Wallet::Wallet> wallet_;
    shared_ptr<Wallet::NanoPay> nanopay_;
    shared_ptr<boost::asio::high_resolution_timer> nanopay_sender_timer_;
    shared_ptr<node_info> ni_;
    string remote_beneficiary_;
    bool *stop_;

private:
    unsigned char nonce_[32]{};
    unsigned char remote_pk_[crypto_sign_ed25519_PUBLICKEYBYTES]{};
    unsigned char pk_[crypto_sign_ed25519_PUBLICKEYBYTES]{};
    unsigned char sk_[crypto_sign_ed25519_SECRETKEYBYTES]{};
    unsigned char curve_pk_[crypto_box_curve25519xchacha20poly1305_PUBLICKEYBYTES]{};
    unsigned char curve_sk_[crypto_box_curve25519xchacha20poly1305_SECRETKEYBYTES]{};
    unsigned char shared_[crypto_box_BEFORENMBYTES]{};
    unsigned char enc_key_[crypto_box_curve25519xchacha20poly1305_SECRETKEYBYTES]{};

private:
    char conn_metadata_[128];
};


#endif //ENTRY_NKN_LOCAL_H
