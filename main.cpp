#include <memory>
#include <boost/asio.hpp>
#include <boost/fiber/fiber.hpp>
#include <thread>

#include "entry.h"
#include "tuna_exit.h"


using boost::asio::ip::tcp;

int start_entry(string ip, int port, string seed, string pk, string metadata, bool *stop) {
    boost::asio::io_context io_context;
    tcp::endpoint from(boost::asio::ip::address::from_string(ip), port);
    auto ni = get_node_info_from_metadata(metadata, pk);
    auto en = std::make_shared<entry>(io_context, from, seed, ni, stop);
    en->run();

    io_context.run();
    return 0;
}

int start_exit(string ip, int port, string seed, string pk, string metadata, bool *stop) {
    boost::asio::io_context io_context;
    tcp::endpoint to(boost::asio::ip::address::from_string(ip), port);
    //auto ni = get_node_info_from_metadata(metadata, pk);
    auto ni = make_shared<node_info>(node_info{"127.0.0.1", 30020, 0, "0", "NKNZ3rqek8Nw5cqcAPfJbkQeFiEYF443A35R",
                                               "aa2c82d22cbec6dde57bbf82cdcdef0f04c56f21f1df9ae2f68ae5f0a9810091"});
    auto ex = std::make_shared<tuna_exit>(io_context, to, seed, ni, stop);
    ex->run();

    io_context.run();
    return 0;
}

int main() {
    string seed = "8f42614443c8f0dd56d110def7efd64cd7954393c16b5af39da88ac4805e2cd7";
    //string pk = "7c2ebcc959fd076505377eb2105472612db9dae467f6f2c538df6c6ba6c189ad";
    //string metadata = "\"Cg02NC42NC4yNDUuMTQ5ELrqARi76gE6BTAuMDAw\"";
    string pk = "7c2ebcc959fd076505377eb2105472612db9dae467f6f2c538df6c6ba6c189ad";
    string metadata = "\"Cg02NC42NC4yNDUuMTQ5ELrqARi76gEgAToEMC4wMQ==\"";
    auto stop = new bool(false);
    start_entry("127.0.0.1", 2015, seed, pk, metadata, stop);
    //start_exit("127.0.0.1", 30488, seed, pk, metadata, stop);
    // cout << ToString(0.00000108) << endl;
    //auto ni = get_node_info_from_pubsub("tuna_v1.outline", "7c2ebcc959fd076505377eb2105472612db9dae467f6f2c538df6c6ba6c189ad");
    return 0;
}

class m {
public:
    int run_main(char *ip, int port, char *seed, char *pk, char *metadata, bool *stop);
};


int m::run_main(char *ip, int port, char *seed, char *pk, char *metadata, bool *stop) {
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