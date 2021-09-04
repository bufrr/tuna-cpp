#ifndef NKN_H
#define NKN_H

#include <iomanip>
#include <boost/asio.hpp>

#include "include/crypto/ed25519.h"
#include "include/wallet.h"
#include "pb/tuna.pb.h"
#include "smux-cpp/encoding.h"
#include "base64.hpp"


using boost::asio::ip::tcp;
using namespace NKN;

struct node_info {
    std::string ip;
    uint port;
    uint service_id;
    std::string price;
    std::string beneficiary_addr;
    std::string pubkey;
};

struct service {
    uint service_id;
    uint port;
    std::string service_name;
};

shared_ptr<node_info> get_node_info_from_pubsub(const string &topic, const string &pk);

shared_ptr<node_info> get_node_info_from_metadata(const char* metadata);

uint32_t read_var_bytes(std::shared_ptr<tcp::socket> s, char *buf);

void write_var_bytes(std::shared_ptr<tcp::socket> s, char *buf, std::size_t len);


template<typename T>
inline std::string ToString(T value) {
    std::stringstream out;
    out << std::fixed;
    out << std::setprecision(8);
    out << value;
    return out.str();
}

#endif // NKN_H