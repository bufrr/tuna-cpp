#include <memory>
#include <boost/asio.hpp>
#include <boost/fiber/fiber.hpp>
#include <thread>

#include "entry.h"


using boost::asio::ip::tcp;

int start_entry(string ip, int port, string seed, string pk, string metadata, bool *stop) {
    boost::asio::io_context io_context;
    tcp::endpoint from(boost::asio::ip::address::from_string(ip), port);
    auto ni = get_node_info_from_metadata(std::move(metadata), pk);
    auto e = std::make_shared<entry>(io_context, from, seed, ni, stop);
    e->run();

    io_context.run();
    return 0;
}

int main() {
    string seed = "8f42614443c8f0dd56d110def7efd64cd7954393c16b5af39da88ac4805e2cd7";
    //string pk = "7c2ebcc959fd076505377eb2105472612db9dae467f6f2c538df6c6ba6c189ad";
    //string metadata = "\"Cg02NC42NC4yNDUuMTQ5ELrqARi76gE6BTAuMDAw\"";
    string pk = "7c2ebcc959fd076505377eb2105472612db9dae467f6f2c538df6c6ba6c189ad";
    string metadata = "\"Cg02NC42NC4yNDUuMTQ5ELrqARi76gE6BTAuMDAx\"";
    auto stop = new bool(false);
    start_entry("127.0.0.1", 2015, seed, pk, metadata, stop);
    // cout << ToString(0.00000108) << endl;
    // auto ni = get_node_info_from_pubsub("tuna_v1.outline", "7c2ebcc959fd076505377eb2105472612db9dae467f6f2c538df6c6ba6c189ad");
    return 0;
}

class m {
public:
    int run_main(char *ip, int port, char *seed, char *pk, char *metadata, bool* stop);
};


int m::run_main(char *ip, int port, char *seed, char *pk, char *metadata, bool* stop) {
    cout << "run_main()" << endl;
    start_entry(string(ip), port, string(seed), string(pk), string(metadata), stop);

    return 0;
}

//class m {
//public:
//    int run_main();
//};
//
//int m::run_main() {
//    string seed = "8f42614443c8f0dd56d110def7efd64cd7954393c16b5af39da88ac4805e2cd7";
//    string pk = "7c2ebcc959fd076505377eb2105472612db9dae467f6f2c538df6c6ba6c189ad";
//    string metadata = "\"Cg02NC42NC4yNDUuMTQ5ELrqARi76gE6BTAuMDAw\"";
//    auto stop = new bool(false);
//    start_entry("127.0.0.1", 2015, seed, pk, metadata, stop);
//    // cout << ToString(0.00000108) << endl;
//    return 0;
//}