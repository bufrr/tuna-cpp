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
    auto en = make_shared<entry>(io_context, from, seed, nis, stop);
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
        ni->pubkey = string(pubkey);
        index++;
    }
    start_entry(nis, ip, port, string(seed), stop);

    return 0;
}

int m::run_main_no_args() {
    cout << "run_main_no_args()" << endl;
    bool stop = false;
    string ip = "127.0.0.1";
    int port = 2022;
    string seed = "9df9843259353211b169b3390eec621925a29d5932e9826792e79a1558df0fb8";
    string pk = R"(["4341e9f8333e7794c75b8ddd9db27a77bedf5fe68aeb59c6e6928be6e7d3b41a"])";
    string metadata = R"(["Cg02NC42NC4yNDUuMTQ5ELrqARi76gEgAjoGMC4wMDAyQiROS05OdHZyaGVMOU5UWWdaVTRqVnJiaTYzQU01Q3NnSkRNWnU="])";
    //string pk = R"(["7e7d45eb6ad0701d3edbdad1a5cc69392a1adfc88ca05ed1834038995265133c"])";
    //string metadata = R"(["Cg8yMDYuMTkwLjIzNS4xOTQQuuoBGLvqASACOgYwLjAwMDJCJE5LTk50dnJoZUw5TlRZZ1pVNGpWcmJpNjNBTTVDc2dKRE1adQ=="])";


    return run_main(const_cast<char *>(ip.c_str()), port, const_cast<char *>(seed.c_str()),
                    const_cast<char *>(pk.c_str()), const_cast<char *>(metadata.c_str()), &stop);
    // cout << ToString(0.00000108) << endl;
}
