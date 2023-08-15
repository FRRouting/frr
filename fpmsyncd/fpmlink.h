#ifndef __FPMLINK__
#define __FPMLINK__

#include <arpa/inet.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include <errno.h>
#include <assert.h>
#include <unistd.h>
#include <exception>

#include "fpm/fpm.h"
#include "zlog.h"

#include "fpmparser.h"

class FpmLink {
      public:
		const int MSG_BATCH_SIZE;
		FpmLink(unsigned short port = FPM_DEFAULT_PORT);
		virtual ~FpmLink();

		/* Wait for connection (blocking) */
		void accept();


		void readData() ;
		/* readMe throws FpmConnectionClosedException when connection is lost */
		class FpmConnectionClosedException : public std::exception {
		};

		/* Check if the netlink message needs to be processed as raw format */
		bool isRawProcessing(struct nlmsghdr *h);


		void epoll();
		void process_fpm_msg(fpm_msg_hdr_t *hdr);

		
      private:
		unsigned int m_bufSize; /* Size of m_messageBuffer */
		char *m_messageBuffer;	/* Buffer for incoming messages */
		unsigned int m_pos;	/* Current position in m_messageBuffer */

		int m_server_socket;	 /* Fpmlink server listen socket */
		int m_connection_socket; /* Fpmlink connection socket */

		static void parse(struct nl_object *obj, void* arg);
};



#endif
