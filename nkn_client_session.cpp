//
// Created by yc chow on 2021/2/7.
//

#include "nkn_client_session.h"


nkn_client_session::nkn_client_session(std::shared_ptr<tcp::socket> sock, std::shared_ptr<smux_sess> sess)
        : client_session(sock, sess) {
}

void nkn_client_session::run(uint service_id) {
    TRACE
    async_write_stream_metadata(0, service_id, false);
}

void nkn_client_session::async_write_stream_metadata(int port_id, int service_id, bool is_payment) {
    auto self = shared_from_this();

    auto md = std::make_shared<pb::StreamMetadata>();
    md->set_port_id(port_id);
    md->set_service_id(service_id);
    md->set_is_payment(is_payment);
    size_t md_buf_len = md->ByteSizeLong();
    char buff[md_buf_len];

    md->SerializeToArray(buff, md_buf_len);
    char len_buf[4];
    encode32u(reinterpret_cast<byte *>(len_buf), md_buf_len);
    char *buf_with_len = static_cast<char *>(malloc(md_buf_len + 4));
    memcpy(buf_with_len, len_buf, 4);
    memcpy(buf_with_len + 4, buff, md_buf_len);
    sess_->async_write(buf_with_len, md_buf_len + 4,
                       [this, self, buf_with_len](std::error_code ec, std::size_t) {
                           free(buf_with_len);
                           client_session::run();
                       });
}
