.. _grpc-dev:

***************
Northbound gRPC
***************

To enable gRPC support one needs to add `--enable-grpc` when running
`configure`. Additionally, when launching each daemon one needs to request
the gRPC module be loaded and which port to bind to. This can be done by adding
`-M grpc:<port>` to the daemon's CLI arguments.

Currently there is no gRPC "routing" so you will need to bind your gRPC
`channel` to the particular daemon's gRPC port to interact with that daemon's
gRPC northbound interface.

The minimum version of gRPC known to work is 1.16.1.

.. _grpc-languages-bindings:

Programming Language Bindings
=============================

The gRPC supported programming language bindings can be found here:
https://grpc.io/docs/languages/

After picking a programming language that supports gRPC bindings, the
next step is to generate the FRR northbound bindings. To generate the
northbound bindings you'll need the programming language binding
generator tools and those are language specific.

C++ Example
-----------

The next sections will use C++ as an example for accessing FRR
northbound through gRPC.

.. _grpc-c++-generate:

Generating C++ FRR Bindings
^^^^^^^^^^^^^^^^^^^^^^^^^^^

Generating FRR northbound bindings for C++ example:

::

   # Install gRPC (e.g., on Ubuntu 20.04)
   sudo apt-get install libgrpc++-dev libgrpc-dev

   mkdir /tmp/frr-cpp
   cd grpc

   protoc --cpp_out=/tmp/frr-cpp \
          --grpc_out=/tmp/frr-cpp \
          -I $(pwd) \
          --plugin=protoc-gen-grpc=`which grpc_cpp_plugin` \
           frr-northbound.proto


.. _grpc-c++-if-sample:

Using C++ To Get Version and Interfaces State
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Below is a sample program to print all interfaces discovered.

::

  # test.cpp
  #include <string>
  #include <sstream>
  #include <grpc/grpc.h>
  #include <grpcpp/create_channel.h>
  #include "frr-northbound.pb.h"
  #include "frr-northbound.grpc.pb.h"

  int main() {
      frr::GetRequest request;
      frr::GetResponse reply;
      grpc::ClientContext context;
      grpc::Status status;

      auto channel = grpc::CreateChannel("localhost:50051",
  				       grpc::InsecureChannelCredentials());
      auto stub = frr::Northbound::NewStub(channel);

      request.set_type(frr::GetRequest::ALL);
      request.set_encoding(frr::JSON);
      request.set_with_defaults(true);
      request.add_path("/frr-interface:lib");
      auto stream = stub->Get(&context, request);

      std::ostringstream ss;
      while (stream->Read(&reply))
        ss << reply.data().data() << std::endl;

      status = stream->Finish();
      assert(status.ok());
      std::cout << "Interface Info:\n" << ss.str() << std::endl;
  }

Below is how to compile and run the program, with the example output:

::

  $ g++ -o test test.cpp frr-northbound.grpc.pb.cc frr-northbound.pb.cc -lgrpc++ -lprotobuf
  $ ./test
  Interface Info:
  {
    "frr-interface:lib": {
      "interface": [
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
              "down-count": 0,
              "ptm-status": "disabled"
            }
          }
        },
        {
          "name": "r1-eth0",
          "vrf": "default",
          "state": {
            "if-index": 2,
            "mtu": 1500,
            "mtu6": 1500,
            "speed": 10000,
            "metric": 0,
            "phy-address": "02:37:ac:63:59:b9"
          },
          "frr-zebra:zebra": {
            "state": {
              "up-count": 0,
              "down-count": 0,
              "ptm-status": "disabled"
            }
          }
        }
      ]
    },
    "frr-zebra:zebra": {
      "mcast-rpf-lookup": "mrib-then-urib",
      "workqueue-hold-timer": 10,
      "zapi-packets": 1000,
      "import-kernel-table": {
        "distance": 15
      },
      "dplane-queue-limit": 200
    }
  }



.. _grpc-python-example:

Python Example
--------------

The next sections will use Python as an example for writing scripts to use
the northbound.

.. _grpc-python-generate:

Generating Python FRR Bindings
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Generating FRR northbound bindings for Python example:

::

   # Install python3 virtual environment capability e.g.,
   sudo apt-get install python3-venv

   # Create a virtual environment for python grpc and activate
   python3 -m venv venv-grpc
   source venv-grpc/bin/activate

   # Install grpc requirements
   pip install grpcio grpcio-tools

   mkdir /tmp/frr-python
   cd grpc

   python3 -m grpc_tools.protoc  \
           --python_out=/tmp/frr-python \
           --grpc_python_out=/tmp/frr-python \
           -I $(pwd) \
           frr-northbound.proto

.. _grpc-python-if-sample:

Using Python To Get Capabilities and Interfaces State
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Below is a sample script to print capabilities and all interfaces Python
discovered. This demostrates the 2 different RPC results one gets from gRPC,
Unary (`GetCapabilities`) and Streaming (`Get`) for the interface state.

::

  import grpc
  import frr_northbound_pb2
  import frr_northbound_pb2_grpc

  channel = grpc.insecure_channel('localhost:50051')
  stub = frr_northbound_pb2_grpc.NorthboundStub(channel)

  # Print Capabilities
  request = frr_northbound_pb2.GetCapabilitiesRequest()
  response = stub.GetCapabilities(request)
  print(response)

  # Print Interface State and Config
  request = frr_northbound_pb2.GetRequest()
  request.path.append("/frr-interface:lib")
  request.type=frr_northbound_pb2.GetRequest.ALL
  request.encoding=frr_northbound_pb2.XML

  for r in stub.Get(request):
      print(r.data.data)

The previous script will output something like:

::

  frr_version: "7.7-dev-my-manual-build"
  rollback_support: true
  supported_modules {
    name: "frr-filter"
    organization: "FRRouting"
    revision: "2019-07-04"
  }
  supported_modules {
    name: "frr-interface"
    organization: "FRRouting"
    revision: "2020-02-05"
  }
  [...]
  supported_encodings: JSON
  supported_encodings: XML

  <lib xmlns="http://frrouting.org/yang/interface">
    <interface>
      <name>lo</name>
      <vrf>default</vrf>
      <state>
        <if-index>1</if-index>
        <mtu>0</mtu>
        <mtu6>65536</mtu6>
        <speed>0</speed>
        <metric>0</metric>
        <phy-address>00:00:00:00:00:00</phy-address>
      </state>
      <zebra xmlns="http://frrouting.org/yang/zebra">
        <state>
          <up-count>0</up-count>
          <down-count>0</down-count>
        </state>
      </zebra>
    </interface>
    <interface>
      <name>r1-eth0</name>
      <vrf>default</vrf>
      <state>
        <if-index>2</if-index>
        <mtu>1500</mtu>
        <mtu6>1500</mtu6>
        <speed>10000</speed>
        <metric>0</metric>
        <phy-address>f2:62:2e:f3:4c:e4</phy-address>
      </state>
      <zebra xmlns="http://frrouting.org/yang/zebra">
        <state>
          <up-count>0</up-count>
          <down-count>0</down-count>
        </state>
      </zebra>
    </interface>
  </lib>

.. _grpc-ruby-example:

Ruby Example
------------

Next sections will use Ruby as an example for writing scripts to use
the northbound.

.. _grpc-ruby-generate:

Generating Ruby FRR Bindings
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

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
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

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
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

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
