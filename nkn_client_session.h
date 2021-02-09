//
// Created by yc chow on 2021/2/7.
//

#ifndef ENTRY_NKN_CLIENT_SESSION_H
#define ENTRY_NKN_CLIENT_SESSION_H

#include "smux-cpp/client_session.h"

class nkn_client_session: public client_session {
public:
    nkn_client_session(std::shared_ptr<tcp::socket> sock, std::shared_ptr<smux_sess> sess);

    void run();
    void async_write_stream_metadata(int port_id, int service_id, bool is_payment);
};

#endif //ENTRY_NKN_CLIENT_SESSION_H
