.. _Configuring_Frr_as_a_Route_Server:

*********************************
Configuring Frr as a Route Server
*********************************

The purpose of a Route Server is to centralize the peerings between BGP
speakers. For example if we have an exchange point scenario with four BGP
speakers, each of which maintaining a BGP peering with the other three
(:ref:`fig:full-mesh`), we can convert it into a centralized scenario where
each of the four establishes a single BGP peering against the Route Server
(:ref:`fig:route-server`).

We will first describe briefly the Route Server model implemented by Frr.
We will explain the commands that have been added for configuring that
model. And finally we will show a full example of Frr configured as Route
Server.

