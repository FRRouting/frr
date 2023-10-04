Path Computation Algorithms
===========================

Introduction
------------

Both RSVP-TE and Segment Routing Flex Algo need to compute end to end path
with other constraints as the standard IGP metric. Based on Shortest Path First
(SPF) algorithms, a new class of Constrained SPF (CSPF) is provided by the FRR
library.

Supported constraints are as follow:
- Standard IGP metric (here, CSPF provides the same result as a normal SPF)
- Traffic Engineering (TE) IGP metric
- Delay from the IGP Extended Metrics
- Bandwidth for a given Class of Service (CoS) for bandwidth reservation

Algorithm
---------

The CSPF algorithm is based on a Priority Queue which store the on-going
possible path sorted by their respective weights. This weight corresponds
to the cost of the cuurent path from the source up to the current node.

The algorithm is as followed:

.. code-block:: c

    cost = MAX_COST;
    Priority_Queue.empty();
    Visited_Node.empty();
    Processed_Path.empty();
    src = new_path(source_address);
    src.cost = 0;
    dst = new_destinatio(destination_address);
    dst.cost = MAX_COST;
    Processed_Path.add(src);
    Processed_Path.add(dst);
    while (Priority_Queue.count != 0) {
        current_path = Priority_Queue.pop();
        current_node = next_path.destination;
        Visited_Node.add(current_node);
        for (current_node.edges: edge) {
            if (prune_edge(current_path, edge)
                continue;
            if (relax(current_path) && cost > current_path.cost) {
                optim_path = current_path;
                cost = current_path.cost;
            }
        }
    }

    prune_edge(path, edge) {
        // check that path + edge meet constraints  e.g.
        if (current_path.cost + edge.cost > constrained_cost)
            return false;
        else
            return true;
    }

    relax_edge(current_path, edge) {
        next_node = edge.destination;
        if (Visited_Node.get(next_node))
            return false;
        next_path = Processed_Path.get(edge.destination);
        if (!next_path) {
            next_path = new path(edge.destination);
            Processed_Path.add(next_path);
        }
        total_cost = current_path.cost + edge.cost;
        if (total_cost < next_path.cost) {
            next_path = current_path;
            next_path.add_edge(edge);
            next_path.cost = total_cost;
            Priority_Queue.add(next_path);
        }
        return (next_path.destination == destination);
    }


Definition
----------

.. c:struct:: constraints

This is the constraints structure that contains:

- cost: the total cost that the path must respect
- ctype: type of constraints:

  - CSPF_METRIC for standard metric
  - CSPF_TE_METRIC for TE metric
  - CSPF_DELAY for delay metric

- bw: bandwidth that the path must respect
- cos: Class of Service (COS) for the bandwidth
- family: AF_INET or AF_INET6
- type: RSVP_TE, SR_TE or SRV6_TE

.. c:struct:: c_path

This is the Constraint Path structure that contains:

- edges: List of Edges that compose the path
- status: FAILED, IN_PROGRESS, SUCCESS, NO_SOURCE, NO_DESTINATION, SAME_SRC_DST
- weight: the cost from source to the destination of the path
- dst: key of the destination vertex

.. c:struct:: cspf

This is the main structure for path computation. Even if it is public, you
don't need to set manually the internal field of the structure. Instead, use
the following functions:

.. c:function:: struct cspf *cspf_new(void);

Function to create an empty cspf for future call of path computation

.. c:function:: struct cspf *cspf_init(struct cspf *algo, const struct ls_vertex *src, const struct ls_vertex *dst, struct constraints *csts);

This function initialize the cspf with source and destination vertex and
constraints and return pointer to the cspf structure. If input cspf structure
is NULL, a new cspf structure is allocated and initialize.

.. c:function:: struct cspf *cspf_init_v4(struct cspf *algo, struct ls_ted *ted, const struct in_addr src, const struct in_addr dst, struct constraints *csts);

Same as cspf_init, but here, source and destination vertex are extract from
the TED data base based on respective IPv4 source and destination addresses.

.. c:function:: struct cspf *cspf_init_v6(struct cspf *algo, struct ls_ted *ted, const struct in6_addr src, const struct in6_addr dst, struct constraints *csts);

Same as cspf_init_v4 but with IPv6 source and destination addresses.

.. c:function:: void cspf_clean(struct cspf *algo);

Clean internal structure of cspf in order to reuse it for another path
computation.

.. c:function:: void cspf_del(struct cspf *algo);

Delete cspf structure. A call to cspf_clean() function is perform prior to
free allocated memeory.

.. c:function:: struct c_path *compute_p2p_path(struct ls_ted *ted, struct cspf *algo);

Compute point to point path from the ted and cspf.
The function always return a constraints path. The status of the path gives
indication about the success or failure of the algorithm. If cspf structure has
not been initialize with a call to `cspf_init() or cspf_init_XX()`, the
algorithm returns a constraints path with status set to FAILED.
Note that a call to `cspf_clean()` is performed at the end of this function,
thus it is mandatory to initialize the cspf structure again prior to call again
the path computation algorithm.


Usage
-----

Of course, CSPF algorithm needs a network topology that contains the
various metrics. Link State provides such Traffic Engineering Database.

To perform a Path Computation with given constraints, proceed as follow:

.. code-block:: c

    struct cspf *algo;
    struct ls_ted *ted;
    struct in_addr src;
    struct in_addr dst;
    struct constraints csts;
    struct c_path *path;

    // Create a new CSPF structure
    algo = cspf_new();

    // Initialize constraints
    csts.cost = 100;
    csts.ctype = CSPF_TE_METRIC;
    csts.family = AF_INET;
    csts.type = SR_TE;
    csts.bw = 1000000;
    csts.cos = 3;

    // Then, initialise th CSPF with source, destination and constraints
    cspf_init_v4(algo, ted, src, dst, &csts);

    // Finally, got the Computed Path;
    path = compute_p2p_path(ted, algo);

    if (path.status == SUCCESS)
        zlog_info("Got a valid constraints path");
    else
        zlog_info("Unable to compute constraints path. Got %d status", path->status);


If you would compute another path, you must call `cspf_init()` prior to
`compute_p2p_path()` to change source, destination and/or constraints.
