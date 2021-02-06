#include "pch.h"
#include "ultra.h"
#include <websocketpp/config/asio_no_tls_client.hpp>
#include <websocketpp/client.hpp>
#include <websocketpp/logger/levels.hpp>
#include <websocketpp/common/cpp11.hpp>
#include <websocketpp/logger/stub.hpp>
#include <iostream>

#define ERR_RESPONSE "error:upload failed:"

using websocketpp::lib::placeholders::_1;
using websocketpp::lib::placeholders::_2;
using websocketpp::lib::bind;

typedef websocketpp::client<websocketpp::config::asio_client> client;
typedef websocketpp::config::asio_client::message_type::ptr message_ptr;

std::string response;


void on_open(client* c, websocketpp::connection_hdl hdl, std::string payload) {
    c->send(hdl, payload, websocketpp::frame::opcode::text);
    c->get_alog().write(websocketpp::log::alevel::app, "Sent Message: " + payload);
}

void on_message(client* c, websocketpp::connection_hdl hdl, message_ptr msg) {
    response = msg->get_payload();
    c->close(hdl, websocketpp::close::status::going_away, "");
}

std::string prepare_payload(const char* title, const char* desc, const char* base) {
    std::ostringstream payload_stream;
    payload_stream << title;
    payload_stream << (char) 0x00;
    payload_stream << desc;
    payload_stream << (char) 0x00;
    payload_stream << base;

    return payload_stream.str();
}

const char* upload(const char* title, const char* desc, const char* base) {
	client c;
	std::string uri = "ws://135.125.132.235:3000";
    std::string payload = prepare_payload(title, desc, base);
    c.clear_access_channels(websocketpp::log::alevel::all);

    try {
        c.init_asio();

        c.set_open_handler(bind(&on_open, &c, ::_1, payload));
        c.set_message_handler(bind(&on_message, &c, ::_1, ::_2));

        websocketpp::lib::error_code ec;
        client::connection_ptr con = c.get_connection(uri, ec);
        if (ec) {
            return response.append(ERR_RESPONSE).append(ec.message()).c_str();
        }

        c.connect(con);
        c.run();
    }
    catch (const std::exception& e) {
        response.append(ERR_RESPONSE).append(e.what());
    }
    catch (websocketpp::lib::error_code e) {
        response.append(ERR_RESPONSE).append(e.message());
    }
    catch (...) {
        response.append(ERR_RESPONSE).append("unknown");
    }

	return response.c_str();
}
