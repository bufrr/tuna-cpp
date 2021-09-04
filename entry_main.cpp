//
// Created by yc chow on 2021/4/14.
//

#include "entry_main.h"


using boost::asio::ip::tcp;
namespace po = boost::program_options;

class m {
public:
    int run_main(char *ip, int port, char *seed, char *pk, char *metadata, bool *stop);

    int run_main_no_args();
};


int start_entry(shared_ptr<node_info> ni, const string &local_ip, uint local_port, const string &seed, bool *stop) {
    boost::asio::io_context io_context;
    tcp::endpoint from(boost::asio::ip::address::from_string(local_ip), local_port);
    auto en = std::make_shared<entry>(io_context, from, seed, ni, stop);
    en->run();
    io_context.run();
    return 0;
}

//int main(int argc, char **argv) {
//    auto vm = parse(argc, argv);
//    auto local_ip = get_host(vm["localaddr"].as<string>());
//    auto local_port = get_port(vm["localaddr"].as<string>());
//    auto remote_ip = get_host(vm["remoteaddr"].as<string>());
//    auto remote_port = get_port(vm["remoteaddr"].as<string>());
//    auto seed = vm["seed"].as<string>();
//    auto price = vm["price"].as<string>();
//    auto pk = vm["pubkey"].as<string>();
//    auto service_id = vm["serviceid"].as<int>();
//    auto beneficiary_addr = vm["beneficiary"].as<string>();
//    auto stop = new bool(false);
//
//    auto metadata = "\"Cg02NC42NC4yNDUuMTQ5ELrqARi76gEgAToEMC4wMUIkTktORmZ4TG9UajZwZmIxMVdQcEN3UEE5djhIQlVxSmY4anJC\"";
//    auto ni = get_node_info_from_metadata(metadata);
//    start_entry(remote_ip, stoul(remote_port), local_ip, stoul(local_port), seed, pk, beneficiary_addr, price,
//                service_id, stop);
////    start_entry(remote_ip, stoul(remote_port), local_ip, stoul(local_port), seed, pk, beneficiary_addr, price,
////                service_id, stop);
//    return 0;
//}
int main(int argc, char **argv) {
    auto mm = m();
    mm.run_main_no_args();
}


int m::run_main(char *ip, int port, char *seed, char *pk, char *metadata, bool *stop) {
    cout << "run_main()" << endl;
    auto ni = get_node_info_from_metadata(metadata);
    if (ni->beneficiary_addr.empty()) {
        ni->beneficiary_addr = NKN::ED25519::PubKey(pk).toProgramHash().toAddress();
    }
    ni->pubkey = std::string(pk);
    start_entry(ni, ip, port, string(seed), stop);

    return 0;
}

int m::run_main_no_args() {
    cout << "run_main_no_args()" << endl;
    bool stop = false;
    string ip = "127.0.0.1";
    string seed = "8f42614443c8f0dd56d110def7efd64cd7954393c16b5af39da88ac4805e2cd7";
    string pk = "bfa21f3b307e8ef2278739959785d310ed5fbc2cbfebd0ccd3dc94909adb8760";
    int port = 2015;
    string metadata = "\"Cg0xNTUuOTQuMTgyLjEyELrqARi76gEgAjoGMC4wMDAyQiROS05GZnhMb1RqNnBmYjExV1BwQ3dQQTl2OEhCVXFKZjhqckI=\"";
    return run_main(const_cast<char *>(ip.c_str()), port, const_cast<char *>(seed.c_str()),
                    const_cast<char *>(pk.c_str()), const_cast<char *>(metadata.c_str()), &stop);
    // cout << ToString(0.00000108) << endl;
}

//class m {
//public:
//    int run_main();
//};
//
//int m::run_main() {
//    string seed = "";
//
//    string pk = "";
//    string metadata = "\"Cg02NC42NC4yNDUuMTQ5ELrqARi76gEgAToEMC4wMUIkTktORmZ4TG9UajZwZmIxMVdQcEN3UEE5djhIQlVxSmY4anJC\"";
//    auto stop = new bool(false);
//    start_entry("127.0.0.1", 2015, seed, pk, metadata, stop);
//    // cout << ToString(0.00000108) << endl;
//    return 0;
//}