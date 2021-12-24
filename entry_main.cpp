//
// Created by yc chow on 2021/4/14.
//

#include "entry_main.h"


using boost::asio::ip::tcp;
namespace po = boost::program_options;

class m {
public:
    int run_main(char *ip, int port, char *seed, char *pk, char *metadata_json, bool *stop);

    int run_main_no_args();
};


int start_entry(vector<shared_ptr<node_info>> nis, const string &local_ip, uint local_port, const string &seed,
                bool *stop) {
    boost::asio::io_context io_context;
    tcp::endpoint from(boost::asio::ip::address::from_string(local_ip), local_port);
    auto en = std::make_shared<entry>(io_context, from, seed, nis, stop);
    en->run();
    io_context.run();
    *stop = true;
    return 0;
}

int main(int argc, char **argv) {
    auto mm = m();
    mm.run_main_no_args();
}


int m::run_main(char *ip, int port, char *seed, char *pk, char *metadata, bool *stop) {
    cout << "run_main()" << endl;
    //auto md = string(metadata_json, md_len);
    auto nis = get_node_info_from_metadata(metadata);
    rapidjson::Document doc;
    doc.Parse(pk);
    auto pk_arr = doc.GetArray();
    int index = 0;
    for (auto &ni: nis) {
        auto pubkey = pk_arr[index].GetString();
        if (ni->beneficiary_addr.empty()) {
            ni->beneficiary_addr = NKN::ED25519::PubKey(pubkey).toProgramHash().toAddress();
        }
        ni->pubkey = std::string(pubkey);
        index++;
    }
    start_entry(nis, ip, port, string(seed), stop);

    return 0;
}

int m::run_main_no_args() {
    cout << "run_main_no_args()" << endl;
    bool stop = false;
    string ip = "127.0.0.1";
    int port = 2015;
    string seed = "9df9843259353211b169b3390eec621925a29d5932e9826792e79a1558df0fb8";
    string pk = R"(["b22be0cc0e9bcaa29cc90ee7469e0e8f48b1f7848c2a5573f17bbed1254e3e74", "7c2ebcc959fd076505377eb2105472612db9dae467f6f2c538df6c6ba6c189ad"])";
    string metadata = R"(["Cg0xOC4yMTIuMTg1LjUzELrqARi76gEgAjoGMC4wMDAyQiROS05UNjFMdkJzQlNLblpZdE03TVk5dVY2VFlmZzllU1g4Ulc=", "Cg02NC42NC4yNDUuMTQ5EMTqARjF6gE6BjAuMDAwMg=="])";

    return run_main(const_cast<char *>(ip.c_str()), port, const_cast<char *>(seed.c_str()),
                    const_cast<char *>(pk.c_str()), const_cast<char *>(metadata.c_str()), &stop);
    // cout << ToString(0.00000108) << endl;
}
