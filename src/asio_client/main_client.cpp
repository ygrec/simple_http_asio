//#ifdef WIN32
//#define _WIN32_WINNT 0x0501
//#include <stdio.h>
//#endif


//#include <boost/thread.hpp>
//#include <boost/bind.hpp>
//#include <boost/asio.hpp>
//#include <boost/shared_ptr.hpp>
//#include <boost/enable_shared_from_this.hpp>

#include "client.hpp"
//using namespace boost::asio;
//io_service service;


int main(int argc, char* argv[]) {
    // connect several clients
    ip::tcp::endpoint ep( ip::address::from_string("127.0.0.1"), 8001);
    char* names[] = { "John", "James", "Lucy", "Tracy", "Frank", "Abby", 0 };
    for ( char ** name = names; *name; ++name) {
        talk_to_svr::start(ep, *name);
        boost::this_thread::sleep( boost::posix_time::millisec(100));
    }

    service.run();
}
