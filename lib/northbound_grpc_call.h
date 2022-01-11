/*
 * Copyright (C) 2021, LabN Consulting, L.L.C
 * Copyright (C) 2022 NetDEF, Inc.
 *                    Rafael F. Zalamena
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef NORTHBOUND_GRPC_CALL_H
#define NORTHBOUND_GRPC_CALL_H

#include "lib/northbound_grpc_candidates.h"
#include "lib/thread.h"

/** Pure virtual base class just for avoiding blind casts on queue run. */
class NorthboundCallInterface
{
      public:
	NorthboundCallInterface(frr::Northbound::AsyncService *service,
				grpc::ServerCompletionQueue *queue,
				struct thread_master *main,
				Candidates *candidates, bool *running)
	    : m_service(service), m_queue(queue), m_main(main), cdb(candidates),
	      m_running(running), context(NULL), m_state(call_init)
	{
		pthread_mutex_init(&m_mutex, NULL);
		pthread_cond_init(&m_cond, NULL);
	}

	virtual ~NorthboundCallInterface()
	{
		pthread_mutex_destroy(&m_mutex);
		pthread_cond_destroy(&m_cond);
	}

	/** Run the state machine (called by the server). */
	void run()
	{
		switch (m_state) {
		case call_init:
			request_next();
			m_state = call_process;
			/* FALLTHROUGH */

		case call_process:
			/* Queue callback execution in main process. */
			thread_add_timer_msec(m_main, run_process_callback_main,
					      (void *)this, 0, NULL);

			grpc_lock();
			while (m_state != call_finish)
				pthread_cond_wait(&m_cond, &m_mutex);
			grpc_unlock();
			break;

		case call_finish:
			/* Get rid of this instance. */
			delete this;
			break;
		}
	}

	/** Mark request as finished (called by the process callback). */
	void finish()
	{
		m_state = call_finish;
		grpc_signal();
	}

	/**
	 * Is server shutting down? We need to know in order to avoid
	 * accessing data structures that will be cleaned up.
	 */
	inline bool is_shutdown()
	{
		return !(*m_running);
	}

	// Helper functions for the process callback.
	//
	// **NOTE**
	// Members named without `m_` and as public to avoid rewriting
	// callbacks code.
	void *context;
	Candidates *cdb;

	void grpc_lock()
	{
		pthread_mutex_lock(&m_mutex);
	}
	void grpc_unlock()
	{
		pthread_mutex_unlock(&m_mutex);
	}
	void grpc_signal()
	{
		pthread_cond_signal(&m_cond);
	}
	virtual void grpc_callback() = 0;

      protected:
	/* gRPC related data. */
	grpc::ServerContext m_context;
	grpc::ServerCompletionQueue *m_queue;

	/* FRR related data. */
	frr::Northbound::AsyncService *m_service;
	struct thread_master *m_main;

	/** Server running state. */
	bool *m_running;

	enum {
		/** This is the first time this is called. */
		call_init,
		/** Request is being answered. */
		call_process,
		/** Call finished, free resources. */
		call_finish,
	} m_state;

      private:
	/** Start accepting new process. */
	virtual void request_next() = 0;

	/**
	 * Stop responder so we can shutdown.
	 *
	 * Must be implemented by specialized class due to difference between
	 * `responder` and `async_responder`.
	 */
	virtual void shutdown() = 0;

	/** Class specialized method callback to run in main thread. */
	static int run_process_callback_main(struct thread *t)
	{
		NorthboundCallInterface *tag =
			static_cast<NorthboundCallInterface *>(THREAD_ARG(t));

		// We got called after a shutdown: finish and return.
		if (tag->is_shutdown()) {
			tag->shutdown();
			return 0;
		}

		tag->grpc_lock();
		tag->grpc_callback();
		tag->grpc_unlock();
		return 0;
	}

	/* Thread related variables. */
	pthread_mutex_t m_mutex;
	pthread_cond_t m_cond;
};

/**
 * Northbound call handler for defined messages. Use this to
 * implement the call routines.
 */
template <typename R, typename A>
class NorthboundCall : public NorthboundCallInterface
{
      private:
	/** Callback type definition for a generic request */
	typedef void (frr::Northbound::AsyncService::*request_cb)(
		grpc::ServerContext *, R *,
		grpc::ServerAsyncResponseWriter<A> *, grpc::CompletionQueue *,
		grpc::ServerCompletionQueue *, void *);
	// **NOTE**:
	// It was not possible to use `std::function` / `std::bind` because
	// the compiler couldn't resolve `grpc::ServerAsync(Response)Writer<A>`
	// for template <A>. Feel free to improve or show me how it is done.

	/** Callback for processing request. */
	typedef void (*process_cb)(NorthboundCall<R, A> *);

      public:
	NorthboundCall(frr::Northbound::AsyncService *service,
		       grpc::ServerCompletionQueue *queue,
		       struct thread_master *main, Candidates *candidates,
		       bool *running, request_cb request_callback,
		       process_cb process_callback)
	    : NorthboundCallInterface(service, queue, main, candidates,
				      running),
	      responder(&m_context), m_request_callback(request_callback),
	      m_process_callback(process_callback)
	{
		(m_service->*m_request_callback)(&m_context, &request,
						 &responder, m_queue, m_queue,
						 this);
	}

	virtual void grpc_callback()
	{
		m_process_callback(this);
	}

	A response;
	R request;
	grpc::ServerAsyncResponseWriter<A> responder;

      private:
	virtual void request_next()
	{
		// THIS IS NOT A MEMORY LEAK! Objects `free()`/`delete`
		// themselves when the state `call_finish` is reached or the
		// completion queue is emptied.
		new NorthboundCall<R, A>(m_service, m_queue, m_main, cdb,
					 m_running, m_request_callback,
					 m_process_callback);
	}

	virtual void shutdown()
	{
		if (m_state == call_finish)
			return;

		responder.Finish(response, grpc::Status::CANCELLED, this);
		finish();
	}

	request_cb m_request_callback;
	process_cb m_process_callback;
};

/**
 * Northbound async call handler for defined messages. Use this to
 * implement the call routines.
 */
template <typename R, typename A>
class NorthboundCallAsync : public NorthboundCallInterface
{
      private:
	/** Callback type definition for a generic asynchronous request */
	typedef void (frr::Northbound::AsyncService::*request_async_cb)(
		grpc::ServerContext *, R *, grpc::ServerAsyncWriter<A> *,
		grpc::CompletionQueue *, grpc::ServerCompletionQueue *, void *);

	/** Callback for processing request. */
	typedef void (*process_cb)(NorthboundCallAsync<R, A> *);

      public:
	NorthboundCallAsync(frr::Northbound::AsyncService *service,
			    grpc::ServerCompletionQueue *queue,
			    struct thread_master *main, Candidates *candidates,
			    bool *running, request_async_cb request_callback,
			    process_cb process_callback)
	    : NorthboundCallInterface(service, queue, main, candidates,
				      running),
	      async_responder(&m_context),
	      m_request_async_callback(request_callback),
	      m_process_callback(process_callback)
	{
		(m_service->*m_request_async_callback)(&m_context, &request,
						       &async_responder,
						       m_queue, m_queue, this);
	}

	virtual void grpc_callback()
	{
		m_process_callback(this);
	}

	R request;
	A response;
	grpc::ServerAsyncWriter<A> async_responder;

      private:
	virtual void request_next()
	{
		// THIS IS NOT A MEMORY LEAK! Objects `free()`/`delete`
		// themselves when the state `call_finish` is reached or the
		// completion queue is emptied.
		new NorthboundCallAsync<R, A>(
			m_service, m_queue, m_main, cdb, m_running,
			m_request_async_callback, m_process_callback);
	}

	virtual void shutdown()
	{
		if (m_state == call_finish)
			return;

		async_responder.Finish(grpc::Status::CANCELLED, this);
		finish();
	}

	request_async_cb m_request_async_callback;
	process_cb m_process_callback;
};

#endif /* NORTHBOUND_GRPC_CALL_H */
