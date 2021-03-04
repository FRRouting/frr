.. _grpc-dev:

***************
Northbound gRPC
***************

.. _grpc-languages-bindings:

Programming Language Bindings
=============================

The gRPC supported programming language bindings can be found here:
https://grpc.io/docs/languages/

After picking a programming language that supports gRPC bindings, the
next step is to generate the FRR northbound bindings. To generate the
northbound bindings you'll need the programming language binding
generator tools and those are language specific.

Next sections will use Ruby as an example for writing scripts to use
the northbound.


.. _grpc-ruby-generate:

Generating Ruby FRR Bindings
----------------------------

Generating FRR northbound bindings for Ruby example:

::

   # Install the required gems:
   # - grpc: the gem that will talk with FRR's gRPC plugin.
   # - grpc-tools: the gem that provides the code generator.
   gem install grpc
   gem install grpc-tools

   # Create your project/scripts directory:
   mkdir /tmp/frr-ruby

   # Go to FRR's grpc directory:
   cd grpc

   # Generate the ruby bindings:
   grpc_tools_ruby_protoc \
     --ruby_out=/tmp/frr-ruby \
     --grpc_out=/tmp/frr-ruby \
     frr-northbound.proto


.. _grpc-ruby-if-sample:

Using Ruby To Get Interfaces State
----------------------------------

Here is a sample script to print all interfaces FRR discovered:

::

   require 'frr-northbound_services_pb'

   # Create the connection with FRR's gRPC:
   stub = Frr::Northbound::Stub.new('localhost:50051', :this_channel_is_insecure)

   # Create a new state request to get interface state:
   request = Frr::GetRequest.new
   request.type = :STATE
   request.path.push('/frr-interface:lib')

   # Ask FRR.
   response = stub.get(request)

   # Print the response.
   response.each do |result|
     result.data.data.each_line do |line|
       puts line
     end
   end


.. note::

   The generated files will assume that they are in the search path (e.g.
   inside gem) so you'll need to either edit it to use ``require_relative`` or
   tell Ruby where to look for them. For simplicity we'll use ``-I .`` to tell
   it is in the current directory.


The previous script will output something like this:

::

   $ cd /tmp/frr-ruby
   # Add `-I.` so ruby finds the FRR generated file locally.
   $ ruby -I. interface.rb
   {
     "frr-interface:lib": {
       "interface": [
         {
           "name": "eth0",
           "vrf": "default",
           "state": {
             "if-index": 2,
             "mtu": 1500,
             "mtu6": 1500,
             "speed": 1000,
             "metric": 0,
             "phy-address": "11:22:33:44:55:66"
           },
           "frr-zebra:zebra": {
             "state": {
               "up-count": 0,
               "down-count": 0
             }
           }
         },
         {
           "name": "lo",
           "vrf": "default",
           "state": {
             "if-index": 1,
             "mtu": 0,
             "mtu6": 65536,
             "speed": 0,
             "metric": 0,
             "phy-address": "00:00:00:00:00:00"
           },
           "frr-zebra:zebra": {
             "state": {
               "up-count": 0,
               "down-count": 0
             }
           }
         }
       ]
     }
   }


.. _grpc-ruby-bfd-profile-sample:

Using Ruby To Create BFD Profiles
---------------------------------

In this example you'll learn how to edit configuration using JSON
and programmatic (XPath) format.

::

   require 'frr-northbound_services_pb'

   # Create the connection with FRR's gRPC:
   stub = Frr::Northbound::Stub.new('localhost:50051', :this_channel_is_insecure)

   # Create a new candidate configuration change.
   new_candidate = stub.create_candidate(Frr::CreateCandidateRequest.new)

   # Use JSON to configure.
   request = Frr::LoadToCandidateRequest.new
   request.candidate_id = new_candidate.candidate_id
   request.type = :MERGE
   request.config = Frr::DataTree.new
   request.config.encoding = :JSON
   request.config.data = <<-EOJ
   {
     "frr-bfdd:bfdd": {
       "bfd": {
         "profile": [
           {
             "name": "test-prof",
             "detection-multiplier": 4,
             "required-receive-interval": 800000
           }
         ]
       }
     }
   }
   EOJ

   # Load configuration to candidate.
   stub.load_to_candidate(request)

   # Commit candidate.
   stub.commit(
     Frr::CommitRequest.new(
       candidate_id: new_candidate.candidate_id,
       phase: :ALL,
       comment: 'create test-prof'
     )
   )

   #
   # Now lets delete the previous profile and create a new one.
   #

   # Create a new candidate configuration change.
   new_candidate = stub.create_candidate(Frr::CreateCandidateRequest.new)

   # Edit the configuration candidate.
   request = Frr::EditCandidateRequest.new
   request.candidate_id = new_candidate.candidate_id

   # Delete previously created profile.
   request.delete.push(
     Frr::PathValue.new(
       path: "/frr-bfdd:bfdd/bfd/profile[name='test-prof']",
     )
   )

   # Add new profile with two configurations.
   request.update.push(
     Frr::PathValue.new(
       path: "/frr-bfdd:bfdd/bfd/profile[name='test-prof-2']/detection-multiplier",
       value: 5.to_s
     )
   )
   request.update.push(
     Frr::PathValue.new(
       path: "/frr-bfdd:bfdd/bfd/profile[name='test-prof-2']/desired-transmission-interval",
       value: 900_000.to_s
     )
   )

   # Modify the candidate.
   stub.edit_candidate(request)

   # Commit the candidate configuration.
   stub.commit(
     Frr::CommitRequest.new(
       candidate_id: new_candidate.candidate_id,
       phase: :ALL,
       comment: 'replace test-prof with test-prof-2'
     )
   )


And here is the new FRR configuration:

::

   $ sudo vtysh -c 'show running-config'
   ...
   bfd
    profile test-prof-2
     detect-multiplier 5
     transmit-interval 900
    !
   !
