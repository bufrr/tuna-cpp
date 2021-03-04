//
// Created by yc chow on 2021/2/7.
//

#ifndef ENTRY_NKN_CLIENT_SESSION_H
#define ENTRY_NKN_CLIENT_SESSION_H

#include "smux-cpp/client_session.h"
#include "pb/tuna.pb.h"

class nkn_client_session : public client_session {
public:
    nkn_client_session(std::shared_ptr<tcp::socket> sock, std::shared_ptr<smux_sess> sess);

    void run(uint service_id);

    void run_exit_reverse(uint service_id);

    void async_write_stream_metadata(int port_id, int service_id, bool is_payment);

    void async_write_service_metadata(int port_id, int service_id, bool is_payment);


private:
    void call_this_on_destroy() override;

private:
    char stream_metadata_[128];
};

#endif //ENTRY_NKN_CLIENT_SESSION_H
