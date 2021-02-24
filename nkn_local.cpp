//
// Created by yc chow on 2021/2/7.
//

#include "nkn_local.h"

#include <utility>
#include <memory>

//static kvar nkn_local_kvar("nkn_Local");

nkn_Local::nkn_Local(boost::asio::io_context &io_context, shared_ptr<Wallet::Wallet> w, shared_ptr<node_info> ni,
                     bool *stop)
        : Local(io_context), paid_bytes_(0), total_in_bytes_(0),
          total_out_bytes_(0), ni_(ni), wallet_(std::move(w)), stop_(stop) {
    cerr << "ip: " << ni_->ip << " " << "price: " << ni_->price << endl;
    while (true) {
        auto ec = make_shared<boost::system::error_code>();
        auto ep = make_shared<tcp::endpoint>(boost::asio::ip::address::from_string(ni_->ip), ni_->port);
        auto s = boost::asio::ip::tcp::socket(io_context);
        s.connect(*ep, *ec);
        if (!(*ec)) {
            sock_ = std::make_shared<boost::asio::ip::tcp::socket>(std::move(s));
            break;
        }
        cerr << ec->message() << endl;
        std::this_thread::sleep_for(std::chrono::milliseconds(3000)); // sleep for 1 second
    }

    //generate random keypair
    //unsigned char seed[crypto_sign_ed25519_SEEDBYTES];
    //randombytes_buf(seed, sizeof seed);
    //wallet_->account->PrivateKey.toHexString()
    crypto_sign_ed25519_seed_keypair(pk_, sk_,
                                     reinterpret_cast<const unsigned char *>(wallet_->account->PrivateKey.toHexString().c_str()));

    auto pk = Uint256(0);
    pk.FromHexString(ni->pubkey);
    memcpy(remote_pk_, pk.toBytes().c_str(), sizeof remote_pk_);
    remote_beneficiary_ = ED25519::PubKey(pk).toProgramHash().toAddress();

    //prepare_wallet();
    last_payment_ = boost::posix_time::second_clock::local_time();
}

void nkn_Local::run() {
    TRACE
    auto self = shared_from_this();
    pb::ConnectionMetadata md;
    md.set_encryption_algo(pb::ENCRYPTION_XSALSA20_POLY1305);
    md.set_public_key(pk_, crypto_sign_ed25519_PUBLICKEYBYTES);
    negotiate_conn_metadata(sock_, md);

    out2 = [this, self](char *buf, std::size_t len, Handler handler) mutable {
        if (*stop_) {
            TRACE
            destroy();
        }
        total_out_bytes_ += len;
        unsigned char enc_msg[len + crypto_box_MACBYTES];
        unsigned char nonce[crypto_box_NONCEBYTES];
        randombytes_buf(nonce, crypto_box_NONCEBYTES); // need to update each sending

        crypto_box_easy_afternm(enc_msg, reinterpret_cast<const unsigned char *>(buf), len, nonce, enc_key_);

        //char enc_buf[len + 4 + crypto_box_NONCEBYTES + crypto_box_MACBYTES]; // lost data in stack
        char len_buf[4];
        encode32u(reinterpret_cast<byte *>(len_buf), len + crypto_box_NONCEBYTES + crypto_box_MACBYTES);
        memcpy(send_msg_, len_buf, 4);
        memcpy(&send_msg_[4], reinterpret_cast<const char *>(nonce), crypto_box_NONCEBYTES);
        memcpy(&send_msg_[4 + crypto_box_NONCEBYTES], reinterpret_cast<char *>(enc_msg), len + crypto_box_MACBYTES);

        boost::asio::async_write(*sock_,
                                 boost::asio::buffer(send_msg_, len + 4 + crypto_box_NONCEBYTES + crypto_box_MACBYTES),
                                 [this, self, handler](std::error_code ec, std::size_t len) {
                                     if (ec) {
                                         cout << "async_write err: " << ec.message() << endl;
                                         destroy();
                                     }
                                     handler(ec, len);
                                 });
    };

    in2 = [this, self](char *buf, std::size_t len, Handler handler) mutable {
        //cout << len << "len in" << endl;
        unsigned char nonce[crypto_box_NONCEBYTES];
        memcpy(nonce, buf, crypto_box_NONCEBYTES);
        auto success = crypto_box_open_easy_afternm(reinterpret_cast<unsigned char *>(plain_),
                                                    reinterpret_cast<const unsigned char *>(buf +
                                                                                            crypto_box_NONCEBYTES),
                                                    len - crypto_box_NONCEBYTES,
                                                    nonce, enc_key_);

        std::cout << "decrypt status:" << success << std::endl;

        //unpaid_bytes_ += len;
        total_in_bytes_ += len;
        //auto up = unpaid_bytes_.load();
        //std::cout << "unpaid bytes number: " << up / (1024.0 * 1024) << " M" << std::endl;
        smux_->async_input(plain_, len - crypto_box_NONCEBYTES - crypto_box_MACBYTES,
                           [this, self, handler](std::error_code ec, std::size_t len) {
//                               //unpaid_bytes_.fetch_add(len);
//                               cout << "input: " << len << endl;
                               handler(ec, len);
                           });
    };

    smux_ = std::make_shared<smux>(context_, out2);
    smux_->call_on_destroy([self, this] {
        destroy();
    });

    smux_->run();
    //std::this_thread::sleep_for(std::chrono::milliseconds(1000)); // sleep for 1 second
    //send_payment(99999);

    do_sess_receive();
}

void nkn_Local::async_connect(std::function<void(std::shared_ptr<smux_sess>)> handler) {
    smux_->async_connect(handler);
}

void nkn_Local::do_sess_receive() {
    auto self = shared_from_this();
    boost::asio::async_read(*sock_, boost::asio::buffer(sbuf_, 4),
                            [this, self](std::error_code ec, std::size_t sz) {
                                if (ec) {
                                    TRACE
                                    return;
                                }
                                uint32_t buf_len;
                                decode32u(reinterpret_cast<byte *>(sbuf_), &buf_len);
                                boost::asio::async_read(*sock_, boost::asio::buffer(recv_msg_, buf_len),
                                                        [this, self, buf_len](std::error_code ec,
                                                                              std::size_t sz) {
                                                            in2(recv_msg_, sz,
                                                                [this, self](std::error_code ec, std::size_t) {
                                                                    if (ec) {
                                                                        TRACE
                                                                        return;
                                                                    }
                                                                    do_sess_receive();
                                                                });
                                                        });

                            });
}


void nkn_Local::negotiate_conn_metadata(shared_ptr<tcp::socket> sock, pb::ConnectionMetadata md) {
    auto self = shared_from_this();

    auto read_len = read_var_bytes(sock, conn_metadata_);
    auto conn_md = std::make_shared<pb::ConnectionMetadata>();

    conn_md->ParseFromArray(conn_metadata_, read_len);
    memcpy(nonce_, conn_md->nonce().c_str(), 32);

    size_t conn_md_len = md.ByteSizeLong();
    md.SerializeToArray(conn_metadata_, conn_md_len);
    write_var_bytes(sock, conn_metadata_, conn_md_len);

    crypto_sign_ed25519_pk_to_curve25519(curve_pk_, remote_pk_);
    crypto_sign_ed25519_sk_to_curve25519(curve_sk_, sk_);

    crypto_box_beforenm(shared_, curve_pk_, curve_sk_);
    std::string s1(reinterpret_cast<const char *>(nonce_), 32);
    std::string s2(reinterpret_cast<const char *>(shared_), 32);
    auto ss = s1 + s2;
    crypto_hash_sha256(enc_key_, reinterpret_cast<const unsigned char *>(ss.c_str()), 64);;
}

//void nkn_Local::prepare_wallet() {
//    fstream keystore;
//    char wallet_file[] = "./wallet.json";
//    keystore.open(wallet_file, fstream::in | fstream::out);
//    if (!keystore) {
//        keystore.open(wallet_file, fstream::in | fstream::out | fstream::trunc);
//        auto acc = shared_ptr<Wallet::Account>(new Wallet::Account());
//        auto w_cfg = make_shared<Wallet::WalletCfg>(AES_IV_t::Random<Uint128>(), AES_Key_t::Random<Uint256>(), "");
//        wallet_ = Wallet::NewWallet(acc, w_cfg);
//        keystore << *(wallet_->walletData);
//    } else {
//        std::stringstream buffer;
//        buffer << keystore.rdbuf();
//        auto w = NKN::Wallet::WalletFromJSON(buffer.str(), nullptr);
//        wallet_ = w;
//    }
////    cout << wallet_.PubKey().toHexString() << endl;
////    cout << wallet_.Seed().toHexString() << endl;
////    cout << wallet_.PrivKey().toBytes() << "     " << sizeof wallet_.PrivKey().toBytes().c_str() << endl;
////    cout << wallet_.PubKey().toProgramHash().toAddress() << endl;
//    memcpy(pk_, wallet_->PubKey().toBytes().c_str(), sizeof pk_);
//    memcpy(sk_, wallet_->PrivKey().toBytes().c_str(), sizeof sk_);
////    cout << wallet_.PrivKey().toBytes().size() << endl;
//
//}

void nkn_Local::send_payment(uint32_t sid) {
    auto self = shared_from_this();
    //char seed[] = "8f42614443c8f0dd56d110def7efd64cd7954393c16b5af39da88ac4805e2cd7";

    auto rpc = make_shared<JsonRPC>(GetRandomSeedRPCServerAddr());  // new RPC client

    nanopay_ = Wallet::NanoPay::NewNanoPay(rpc, wallet_, remote_beneficiary_, 0, 2000);    // New Wallet::NanoPay

    smux_->async_write_frame(frame{VERSION, cmdSyn, 0, sid}, nullptr);

    auto md = std::make_shared<pb::StreamMetadata>();
    md->set_port_id(0);
    md->set_service_id(ni_->service_id);
    md->set_is_payment(true);

    size_t md_buf_len = md->ByteSizeLong();
    char stream_md_buf[md_buf_len];
    md->SerializeToArray(stream_md_buf, md_buf_len);
    char len_buf[4];
    encode32u(reinterpret_cast<byte *>(len_buf), md_buf_len);
    char buf_with_len[md_buf_len + 4];
    memcpy(buf_with_len, len_buf, 4);
    memcpy(buf_with_len + 4, stream_md_buf, md_buf_len);

    auto f = frame{VERSION, cmdPsh, static_cast<uint16_t>(md_buf_len + 4), sid};

    f.marshal(stream_metadata_buf_);
    memcpy(stream_metadata_buf_ + headerSize, buf_with_len, md_buf_len + 4);
    smux_->async_write(stream_metadata_buf_, headerSize + md_buf_len + 4, [this, self, sid]
            (std::error_code ec, std::size_t) {
        payment_checker(sid);
    });
}

void nkn_Local::payment_checker(uint32_t sid) {
    std::weak_ptr<Local> weak_local = shared_from_this();
    //cout << "payment checker" << endl;
    if (!nanopay_sender_timer_) {
        nanopay_sender_timer_ = std::make_shared<boost::asio::high_resolution_timer>(
                context_, std::chrono::milliseconds(1000));
    } else {
        nanopay_sender_timer_->expires_at(
                nanopay_sender_timer_->expires_at() +
                std::chrono::milliseconds(1000));
    }
    nanopay_sender_timer_->async_wait(
            [this, weak_local, sid](const std::error_code &) {
                auto s = weak_local.lock();
                if (!s || is_destroyed()) {
                    return;
                }

                //auto unpaid_bytes = unpaid_bytes_.load();
                auto unpaid_bytes = total_in_bytes_.load() + total_out_bytes_.load() - paid_bytes_.load();
                auto now = boost::posix_time::second_clock::local_time();
                auto duration = now - last_payment_;
                if (unpaid_bytes >= 32 * 1024 * 1024 || (duration.total_seconds() > 60 && unpaid_bytes > 0)) {
                    auto price = stof(ni_->price);
                    string cost = ToString(price * unpaid_bytes / (1024 * 1024));
                    cout << "cost:" << cost << endl;
                    cout << "duration:" << duration.total_seconds() << endl;
                    std::error_code ec;
                    shared_ptr<pb::Transaction> npTxn;
                    for (int i = 0; i < 3; i++) {
                        npTxn = nanopay_->IncrementAmount(cost, ec);
                        if (ec) {
                            cerr << ec.message() << endl;
                            continue;
                        }
                        break;
                    }
                    TXN::SignTransaction(npTxn, wallet_->account);
                    auto tx_payload_len = npTxn->ByteSizeLong();
                    char payload[tx_payload_len];
                    npTxn->SerializeToArray(payload, tx_payload_len);
                    auto payload_str = npTxn->SerializeAsString();
                    //cout << "str:" << HEX::EncodeToString(payload_str) << endl;
                    char len_buf[4];
                    encode32u(reinterpret_cast<byte *>(len_buf), tx_payload_len);
                    char nanopay_with_len[tx_payload_len + 4];
                    memcpy(nanopay_with_len, len_buf, 4);
                    memcpy(nanopay_with_len + 4, payload, tx_payload_len);
                    auto f1 = frame{VERSION, cmdPsh, static_cast<uint16_t>(sizeof nanopay_with_len), sid};
                    f1.marshal(nanopay_buf_);
                    memcpy(nanopay_buf_ + headerSize, nanopay_with_len, sizeof nanopay_with_len);
                    smux_->async_write(nanopay_buf_, tx_payload_len + 4 + headerSize,
                                       [this, weak_local, unpaid_bytes, now](std::error_code, std::size_t) {
                                           //unpaid_bytes_ -= unpaid_bytes;
                                           paid_bytes_ += unpaid_bytes;
                                           last_payment_ = now;
                                       });
                }
                payment_checker(sid);
            });
}




