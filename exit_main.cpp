//
// Created by yc chow on 2021/4/8.
//

#include "exit_main.h"


int start_exit(string remote_ip, uint remote_port, string local_ip, uint local_port, string seed, string pk,
               string beneficiary_addr, string price,
               uint service_id,
               bool *stop) {
    //tcp::endpoint remote_ep(boost::asio::ip::address::from_string(ni->ip), ni->port);
    while (true) {
        if (*stop) {
            break;
        }
        boost::asio::io_context io_context;
        //auto ni = get_node_info_from_metadata(metadata, pk);
        auto ni = make_shared<node_info>(node_info{remote_ip, remote_port, service_id, price, beneficiary_addr, pk});
        auto ex = std::make_shared<tuna_exit>(io_context, seed, local_ip, local_port, ni, stop);
        ex->run();
        io_context.run();
    }
    return 0;
}

int main(int argc, char **argv) {
    auto vm = parse(argc, argv);
    auto local_ip = get_host(vm["localaddr"].as<string>());
    auto local_port = get_port(vm["localaddr"].as<string>());
    auto remote_ip = get_host(vm["remoteaddr"].as<string>());
    auto remote_port = get_port(vm["remoteaddr"].as<string>());
    auto seed = vm["seed"].as<string>();
    auto price = vm["price"].as<string>();
    auto pk = vm["pubkey"].as<string>();
    auto service_id = vm["serviceid"].as<int>();
    auto beneficiary_addr = vm["beneficiary"].as<string>();
    auto stop = new bool(false);
    start_exit(remote_ip, stoul(remote_port), local_ip, stoul(local_port), seed, pk, beneficiary_addr, price,
               service_id, stop);
    // cout << ToString(0.00000108) << endl;
    //auto ni = get_node_info_from_pubsub("tuna_v1.outline", "7c2ebcc959fd076505377eb2105472612db9dae467f6f2c538df6c6ba6c189ad");
    return 0;
}
