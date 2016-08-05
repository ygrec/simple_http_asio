/*
 * client.hpp
 *
 *  Created on: 30 ���� 2016 �.
 *      Author: i.brickii
 */

//#include <iostream>
//#include <string>
//#include <boost/thread.hpp>
//#include <boost/bind.hpp>
//#include <boost/asio.hpp>
//#include <boost/asio/ip/basic_endpoint.hpp>
//#include <iostream>
//#include <bits/shared_ptr.h>

#ifdef WIN32
#define _WIN32_WINNT 0x0501
#include <stdio.h>
#endif

#include "common.hpp"

#include <boost/thread.hpp>
#include <boost/bind.hpp>
#include <boost/asio.hpp>
#include <boost/shared_ptr.hpp>
#include <boost/enable_shared_from_this.hpp>
using namespace boost::asio;

#define MEM_FN(x)       boost::bind(&self_type::x, shared_from_this())
#define MEM_FN1(x,y)    boost::bind(&self_type::x, shared_from_this(),y)
#define MEM_FN2(x,y,z)  boost::bind(&self_type::x, shared_from_this(),y,z)


/** simple connection to server:
    - logs in just with username (no password)
    - all connections are initiated by the client: client asks, server answers
    - server disconnects any client that hasn't pinged for 5 seconds
    Possible requests:
    - gets a list of all connected clients
    - ping: the server answers either with "ping ok" or "ping client_list_changed"
*/
class talk_to_svr : public boost::enable_shared_from_this<talk_to_svr>
                  , boost::noncopyable {
private:
	static ip::tcp::endpoint CacheEndPoint;


    typedef talk_to_svr self_type;
    talk_to_svr(const std::string & username);
    void start();
public:
    typedef boost::system::error_code error_code;
    typedef boost::shared_ptr<talk_to_svr> ptr;

    static ptr start(ip::tcp::endpoint ep, const std::string & username);
    void stop();
    bool started();
private:
    void on_connect(const error_code & err);
	void on_read(const error_code & err, size_t bytes);
	void on_login();
	void on_ping(const std::string & msg);
	void on_clients(const std::string & msg);
	void do_ping();
	void postpone_ping();
	void do_ask_clients();
	void on_write(const error_code & err, size_t bytes);
	void do_read();
	void do_write(const std::string & msg);
	size_t read_complete(const boost::system::error_code & err, size_t bytes);
private:
    ip::tcp::socket sock_;
    enum { max_msg = 1024 };
    char read_buffer_[max_msg];
    char write_buffer_[max_msg];
    bool started_;
    std::string username_;
    deadline_timer timer_;

    static uint32_t MaxThreadCount;
    uint32_t CurrentThreadNumber;
    const uint32_t MaxConnectionAttempt = 10;
    uint32_t connectionAttemtpCounter;
};
