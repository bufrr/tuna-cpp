#include "nkn.h"
#include "base64.hpp"

shared_ptr<node_info> get_node_info_from_pubsub(const string &topic, const string &pk) {
    json::value params = json::value::object();
    std::string uri("seed.nkn.org");
    std::string get_subscribers_count("getsubscriberscount");
    std::string get_subscription("getsubscription");
    // type convertor

    params["topic"] = json::value(topic);
    params["subscriber"] = json::value(pk);
    auto subscriber = RPCCall(get_subscription, params);
    rapidjson::Document doc;
    auto dd = subscriber["meta"].serialize();
    doc.Parse(subscriber["meta"].serialize().c_str());

    auto service_md = std::make_shared<pb::ServiceMetadata>();
    auto decoded = base64::decode(doc.GetString());
    std::string raw_md(begin(decoded), end(decoded));
    service_md->ParseFromArray(raw_md.c_str(), raw_md.length());

    auto ip = service_md->ip();
    auto price = service_md->price();
    auto port = service_md->tcp_port();
    auto beneficiary_addr = service_md->beneficiary_addr();
    if (beneficiary_addr.empty()) {
        beneficiary_addr = NKN::ED25519::PubKey(pk).toProgramHash().toAddress();
    }
    auto ni = make_shared<node_info>(node_info{ip, port, price, beneficiary_addr, pk});
    std::cout << ni->pubkey << std::endl;
    return ni;
}

shared_ptr<node_info> get_node_info_from_metadata(const string &metadata, const string &pk) {
    rapidjson::Document doc;
    doc.Parse(metadata.c_str());
    auto service_md = std::make_shared<pb::ServiceMetadata>();
    auto decoded = base64::decode(doc.GetString());
    std::string raw_md(begin(decoded), end(decoded));
    service_md->ParseFromArray(raw_md.c_str(), raw_md.length());

    auto ip = service_md->ip();
    auto price = service_md->price();
    auto port = service_md->tcp_port();
    auto beneficiary_addr = service_md->beneficiary_addr();
    if (beneficiary_addr.empty()) {
        beneficiary_addr = NKN::ED25519::PubKey(pk).toProgramHash().toAddress();
    }

    auto ni = make_shared<node_info>(node_info{ip, port, price, beneficiary_addr, pk});
    return ni;
}

uint32_t read_var_bytes(std::shared_ptr<tcp::socket> s, char *buf) {
    boost::asio::read(*s, boost::asio::buffer(buf, 4));
    uint32_t msg_len;
    decode32u(reinterpret_cast<byte *>(buf), &msg_len);
    boost::asio::read(*s, boost::asio::buffer(buf, msg_len));
    return msg_len;
}

void write_var_bytes(std::shared_ptr<tcp::socket> s, char *buf, std::size_t len) {
    char len_buf[4];
    encode32u(reinterpret_cast<byte *>(len_buf), len);
    boost::asio::write(*s, boost::asio::buffer(len_buf, 4));
    boost::asio::write(*s, boost::asio::buffer(buf, len));
}