.. _mgmtd:

*************************
MGMTd (Management Daemon)
*************************

The FRR Management Daemon (from now on referred to as MGMTd) is a new
centralized entity representing the FRR Management Plane which can take
management requests from any kind of UI/Frontend entity (e.g. CLI, Netconf,
Restconf, Grpc etc.) over a new unified and common Frontend interface and
can help maintain configurational data or retrieve operational data from
any number of FRR managed entities/components that have been integrated
with the new FRR Centralised Management Framework.

For organizing the management data to be owned by the FRR Management plane,
management data is stored in YANG in compliance with a pre-defined set
of YANG based schema. Data shall also be stored/retrieved in YANG format only.

The MGMTd also acts as a separate computational entity for offloading much
of the management related computational overload involved in maintaining of
management data and processing of management requests, from individual
component daemons (which can otherwise be a signficant burden on the individual
components, affecting performance of its other functionalities).

Lastly, the MGMTd works in-tandem with one (or more) MGMT Frontend
Clients and a bunch of MGMT Backend Clients to realize the entirety
of the FRR Management plane. Some of the advanatages of this new framework
are:

 1. Consolidation and management of all Management data by a single entity.
 2. Better control over configuration validation, commit and rollback.
 3. Faster collection of configuration data (without needing to involve
    individual component daemons).
 4. Offload computational burden of YANG data parsing and validations
    of new configuration data being provisoned away from individual
    component daemons
 5. Improve performance of individual component daemons while loading
    huge configuration or retrieving huge operational dataset.

The new FRR Management Daemon consists of the following sub-components:
 - MGMT Frontend Interface
 - MGMT Backend Interface
 - MGMT Transaction Engine

.. _mgmt_fe:

MGMT Frontend Interface
=======================

The MGMT Frontend Interface is a bunch of message-based APIs that lets
any UI/Frontend client to interact with the MGMT daemon to requests a
set of management operations on a specific datastore/database.
Following is a list of databases/datastores supported by the MGMT
Frontend Interface and MGMTd:

 - Candidate Database:

  - Consists of configuration data items only.
  - Data can be edited anytime using SET_CONFIG API.
  - Data can be retrieved anytime using GET_CONFIG/GET_DATA API.

 - Running Database:

  - Consists of configuration data items only.
  - Data cannot be edited using SET_CONFIG API.
  - Data can only be modified using COMMIT_CONFIG API after which un-committed
    data from Candidate database will be first validated and applied to
    individualBackend component(s). Only on successful validation and apply on
    all individual components will the new data be copied over to the Running
    database.
  - Data can be retrieved anytime using GET_CONFIG/GET_DATA API.

 - Startup Database:

  - Consists of configuration data items only.
  - This is a copy of Running database that is stored in persistent
    storage and is used to load configurations on Running database during
    MGMT daemon startup.
  - Data cannot be edited/retrieved directly via Frontend interface.

 - Operational Database:

  - Consists of non-configurational data items.
  - Data is not stored on MGMT daemon. Rather it will be need to be fetched
    in real-time from the corresponding Backend component (if present).
  - Data can be retrieved anytime using GET_DATA API.

Frontend Clients connected to MGMTd via Frontend Interface can themselves have
multiple connections from one (or more) of its own remote clients. The MGMT
Frontend Interface supports reresenting each of the remote clients for a given
Frontend client(e.g. Netconf clients on a single Netconf server) as individual
Frontend Client Sessions. So a single connection from a single Frontend Client
can create more than one Frontend Client sessions.

Following are some of the management operations supported:
 - INIT_SESSION/CLOSE_SESSION: Create/Destroy a session. Rest of all the
   operations are supported only in the context of a specific session.
 - LOCK_DB/UNLOCK_DB: Lock/Unlock Management datastores/databases.
 - GET_CONFIG/GET_DATA: Retrieve configurational/operational data from a
   specific datastore/database.
 - SET_CONFIG/DELETE_CONFIG: Add/Modify/Delete specific data in a specific
   datastore/database.
 - COMMIT_CONFIG: Validate and/or apply the uncommited set of configurations
   from one configuration database to another.
 - Currently committing configurations from Candidate to Running database
   is only allowed, and not vice versa.

The exact set of message-based APIs are represented as Google Protobuf
messages and can be found in the following file distributed with FRR codebase.

.. code-block:: frr

   lib/mgmt.proto

The MGMT daemon implements a MGMT Frontend Server that opens a UNIX
socket-based IPC channel on the following path to listen for incoming
connections from all possible Frontend clients:

.. code-block:: frr

   /var/run/frr/mgmtd_fe.sock

Each connection received from a Frontend client is managed and tracked
as a MGMT Frontend adapter by the MGMT Frontend Adapter sub-component
implemented by MGMTd.

To facilitate faster development/integration of Frontend clients with
MGMT Frontend Interface, a C-based library has been developed. The API
specification of this library can be found at:

.. code-block:: frr

   lib/mgmt_fe_client.h

Following is a list of message types supported on the MGMT Frontend Interface:
 - SESSION_REQ<Client-Connection-Id, Destroy>
 - SESSION_REPLY<Client-Connection-Id, Destroy, Session-Id>
 - LOCK_DB_REQ <Session-Id, Database-Id>
 - LOCK_DB_REPLY <Session-Id, Database-Id>
 - UNLOCK_DB_REQ <Session-Id, Database-Id>
 - UNLOCK_DB_REPLY <Session-Id, Database-Id>
 - GET_CONFIG_REQ <Session-Id, Database-Id, Base-Yang-Xpath>
 - GET_CONFIG_REPLY <Session-Id, Database-Id, Base-Yang-Xpath, Yang-Data-Set>
 - SET_CONFIG_REQ <Session-Id, Database-Id, Base-Yang-Xpath, Delete, ...>
 - SET_CONFIG_REPLY <Session-Id, Database-id, Base-Yang-Xpath, ..., Status>
 - COMMIT_CONFIG_REQ <Session-Id, Source-Db-Id, Dest-Db-Id>
 - COMMIT_CONFIG_REPLY <Session-Id, Source-Db-id, Dest-Db-Id, Status>
 - GET_DATA_REQ <Session-Id, Database-Id, Base-Yang-Xpath>
 - GET_DATA_REPLY <Session-Id, Database-id, Base-Yang-Xpath, Yang-Data-Set>
 - REGISTER_NOTIFY_REQ <Session-Id, Database-Id, Base-Yang-Xpath>
 - DATA_NOTIFY_REQ <Database-Id, Base-Yang-Xpath, Yang-Data-Set>

Please refer to the MGMT Frontend Client Developers Reference and Guide
(coming soon) for more details.

MGMTD Backend Interface
=======================
The MGMT Backend Interface is a bunch of message-based APIs that can be
used by individual component daemons like BGPd, Staticd, Zebra to connect
with MGMTd and utilize the new FRR Management Framework to let any Frontend
clients to retrieve any operational data or manipulate any configuration data
owned by the individual daemon component.

Like the MGMT Frontend Interface, the MGMT Backend Interface is is also
comprised of the following:

 - MGMT Backend Server (running on MGMT daemon)
 - MGMT Backend Adapter (running on MGMT daemon)
 - MGMT Backend client (running on Backend component daemons)

The MGMT Backend Client and MGMT Backend Adapter sub-component communicates
using a specific set of message-based APIs.

The exact set of message-based APIs are represented as Google Protobuf
messages and can be found in the following file distributed with FRR codebase.

.. code-block:: frr

   lib/mgmt.proto

The MGMT daemon implements a MGMT Backend Server that opens a UNIX
socket-based IPC channel on the following path to listen for incoming
connections from all possible Backend clients:

.. code-block:: frr

   /var/run/frr/mgmtd_be.sock

Each connection received from a Backend client is managed and tracked
as a MGMT Backend adapter by the MGMT Backend Adapter sub-component
implemented by MGMTd.

To facilitate faster development/integration of Backend clients with
MGMTd, a C-based library has been developed. The API specification
of this library can be found at:

.. code-block:: frr

   lib/mgmt_be_client.h

Following is a list of message types supported on the MGMT Backend Interface:

 - SUBSCRIBE_REQ <Req-Id, Base-Yang-Xpath, Filter-Type>
 - SUBSCRIBE_REPLY <Req-Id, Status>
 - TXN_REQ <Txn-Id, Create>
 - TXN_REPLY <Txn-Id, Status>
 - CREATE_CFGDATA_REQ <Txn-Id, Req-Id, Batch-Id, ConfigDataContents>
 - CREATE_CFGDATA_ERROR <Txn-Id, Req-Id, Batch-Id, Status>
 - VALIDATE_CFGDATA_REQ <Txn-Id, Batch-Id>
 - VALIDATE_CFGDATA_REPLY <Txn-Id, Batch-Id, Status, ErrorInfo>
 - APPLY_CFGDATA_REQ <Txn-Id, Batch-Id>
 - APPLY_CFGDATA_REPLY <Txn-Id, Batch-Id, Status, ErrorInfo>
 - GET_OPERDATA_REQ <Txn-Id, Base-Yang-Xpath, Filter-Type>
 - GET_OPERDATA_REPLY <Txn-Id, OperDataContents>

Please refer to the MGMT Backend Client Developers Reference and Guide
(coming soon) for more details.

MGMTD Transaction Engine
========================

The MGMT Transaction sub-component is the main brain of the MGMT daemon that
takes management requests from one (or more) Frontend Client translates
them into transactions and drives them to completion in co-oridination with
one (or more) Backend client daemons involved in the request.

A transaction can be seen as a set of management procedures executed over
the Backend Interface with one (or more) individual Backend component
daemons, as a result of some management request initiated from a specific
Frontend client session. These group of operations on the Backend Interface
with one (or more) individual components involved should be executed without
taking any further management requests from other Frontend client sessions.
To maintain this kind of atomic behavior a lock needs to be acquired
(sometimes implicitly if not explicitly) by the corresponding Frontend client
session, on the various datastores/databases involved in the management request
being executed. The same datastores/databases need to be unlocked when all
the procedures have been executed and the transaction is being closed.

Following are some of the transaction types supported by MGMT:

 - Configuration Transactions

  - Used to execute management operations like SET_CONFIG and COMMIT_CONFIG
    that involve writing/over-writing the contents of Candidate and Running
    databases.
  - One (and only) can be created and be in-progress at any given time.
  - Once initiated by a specific Frontend Client session and is still
    in-progress, all subsequent SET_CONFIG and COMMIT_CONFIG operations
    from other Frontend Client sessions will be rejected and responded
    with failure.
  - Requires acquiring write-lock on Candidate (and later Running) databases.

 - Show Transactions

  - Used to execute management operations like GET_CONFIG and GET_DATA
    that involve only reading the contents of Candidate and Running
    databases (and sometimes real-time retrieval of operational data
    from individual component daemons).
  - Multiple instance of this transaction type can be created and be
    in-progress at any given time.
  - However, when a configuration transaction is currently in-progress
    show transaction can be initiated by any Frontend Client session.
  - Requires acquiring read-lock on Candidate and/or Running databases.
  - NOTE: Currently GET_DATA on Operational database is NOT supported. To
    be added in a future time soon.

MGMTD Configuration Rollback and Commit History
===============================================

The MGMT daemon maintains upto 10 last configuration commit buffers
and can rollback the contents of the Running Database to any of the
commit-ids maintained in the commit buffers.

Once the number of commit buffers exceeds 10, the oldest commit
buffer is deleted to make space for the latest commit. Also on
rollback to a specific commit-id, buffer of all the later commits
are deleted from commit record.

Configuration rollback is only allowed via VTYSH shell as of today
and is not possible through the MGMT Frontend interface.

MGMT Configuration commands
===========================

.. clicmd:: mgmt set-config XPATH VALUE

    This command uses a SET_CONFIG request over the MGMT Frontend Interface
    for the specified xpath with specific value. This command is used for
    testing purpose only. But can be used to set configuration data from CLI
    using SET_CONFIG operations.

.. clicmd:: mgmt delete-config XPATH

    This command uses a SET_CONFIG request (with delete option) over the
    MGMT Frontend Interface o delete the YANG data node at the given
    xpath unless it is a key-leaf node(in which case it is not deleted).

.. clicmd:: mgmt load-config FILE <merge|replace>

    This command loads configuration in JSON format from the filepath specified,
    and merges or replaces the Candidate DB as per the option specified.

.. clicmd:: mgmt save-config <candidate|running> FILE

    This command dumps the DB specified in the db-name into the file in JSON
    format. This command in not supported for the Operational DB.

.. clicmd:: mgmt commit abort

    This command will abort any configuration present on the Candidate but not
    been applied to the Running DB.

.. clicmd:: mgmt commit apply

    This command commits any uncommited changes in the Candidate DB to the
    Running DB. It also dumps a copy of the tree in JSON format into
    frr_startup.json.

.. clicmd:: mgmt commit check

    This command validates the configuration but does not apply them to the
    Running DB.

.. clicmd:: mgmt rollback commit-id WORD

    This command rolls back the Running Database contents to the state
    corresponding to the commit-id specified.

.. clicmd:: mgmt rollback last WORD

    This command rolls back the last specified number of recent commits.


MGMT Show commands
==================

.. clicmd:: show mgmt backend-adapter all

    This command shows the backend adapter information and the clients/daemons
    connected to the adapters.

.. clicmd:: show mgmt backend-yang-xpath-registry

    This command shows which Backend adapters are registered for which YANG
    data subtree(s).

.. clicmd:: show mgmt frontend-adapter all [detail]

    This command shows the frontend adapter information and the clients
    connected to the adapters.

.. clicmd:: show mgmt transaction all

    Shows the list of transaction and bunch of information about the transaction.

.. clicmd:: show mgmt get-config [candidate|running] XPATH

    This command uses the GET_CONFIG operation over the MGMT Frontend interface and
    returns the xpaths and values of the nodes of the subtree pointed by the <xpath>.

.. clicmd:: show mgmt get-data [candidate|operation|running] XPATH

    This command uses the GET_DATA operation over the MGMT Frontend interface and
    returns the xpaths and values of the nodes of the subtree pointed by the <xpath>.
    Currenlty supported values for 'candidate' and 'running' only
    ('operational' shall be supported in future soon).

.. clicmd:: show mgmt database-contents [candidate|operation|running] [xpath WORD] [file WORD] json|xml

    This command dumps the subtree pointed by the xpath in JSON or XML format. If filepath is
    not present then the tree will be printed on the shell.

.. clicmd:: show mgmt commit-history

    This command dumps details of upto last 10 commits handled by MGMTd.
