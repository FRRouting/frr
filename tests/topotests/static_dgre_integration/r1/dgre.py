#!/usr/bin/python3
# Copyright 2024 6WIND S.A.

"""
Test script which adds or removes a GRE interface and any associated routes in
a similar manner to the psk-radius dynamic GRE script.
"""

from argparse import ArgumentParser
from dataclasses import dataclass
from ipaddress import ip_network
import os
from secrets import SystemRandom
import socket
from subprocess import DEVNULL
from subprocess import CalledProcessError
from subprocess import run
import sys
from tempfile import NamedTemporaryFile


SCRIPT_NETNS = 'main'

FRR_DAEMON = 'staticd'
VTY_SOCKET_POST = f'frr/{FRR_DAEMON}.vty'


def create_tunnel_interface(ifname, local, remote, netns_priv, l3vrf):
    """
    Create a tunnel between the local and remote addresses with a unique name.

    :arg String name:
        Name to assign to the dynamic interface
    :arg String local:
        The local IP address of the dynamic GRE tunnel.
    :arg String remote:
        The remote IP address of the dynamic GRE tunnel.
    :arg String netns_priv:
        Network namespace to which the interface must be moved.
    :arg String l3vrf:
        vrf interface to which the dynamic interface should be attached, None if not necessary.
    """
    create_iface_cmd = ['ip', 'link', 'add', 'name', ifname, 'type', 'gre', 'local', local, 'remote', remote]
    if run(create_iface_cmd, check=False).returncode != 0:
        sys.exit('failed to create interface in the original netns')

    try:
        netns_args = ['netns', netns_priv] if SCRIPT_NETNS != netns_priv else []
        move_iface_cmd = ['ip', 'link', 'set', 'dev', ifname, *netns_args]
        if run(move_iface_cmd, check=False).returncode != 0:
            sys.exit('failed to move interface to destination netns')

    except BaseException as e:
        run(['ip', 'link', 'delete', 'dev', ifname], check=False)
        raise e

    netns_flag = ['-netns', netns_priv] if netns_priv != 'main' else []

    try:
        set_l3vrf_cmd = ['ip', *netns_flag, 'link', 'set', 'dev', ifname, 'up', 'vrf', l3vrf]
        if l3vrf and run(set_l3vrf_cmd, check=False).returncode != 0:
            sys.exit('failed to bring up and attach interface to l3vrf')

    except BaseException as e:
        run(['ip', *netns_flag, 'link', 'delete', 'dev', ifname], check=False)
        raise e


def delete_tunnel_interface(ifname, netns_priv):
    """
    Create a tunnel between the local and remote addresses with a unique name.

    :arg String name:
        Name to assign to the dynamic interface
    :arg String netns_priv:
        Network namespace in which the interface is located.
    """
    netns_flag = ['-netns', netns_priv] if SCRIPT_NETNS != netns_priv else []
    run(['ip', *netns_flag, 'link', 'delete', ifname], check=True)


def create_route_list(route_attrs):
    """
    Creates a list describing each route that should be installed based on the Framed-IPv6-Route and
    Framed-Route RADIUS attributes as well as the install-routes-to parameter from the interface
    template.

    :arg List route_attrs:
        List of each value from the Framed-Route and Framed-IPv6-Route RADIUS attributes.
    :returns:
        A list of (network, tag) tuples with network being the CIDR representation of the IP subnet
        to route in string form and tag being either None or a string containing a base 10 number.
        For example: [('10.0.0.1/32', None), ('10.0.1.0/24', None), ('10.0.2.0/24', '123')]
    """
    route_list = []

    for attr_value in route_attrs:
        try:
            # Manually parsing the attributes like this is faster than using a regex for now.
            # This may change when more options are added.
            network, *options = attr_value.split()
            network = ip_network(network).with_prefixlen

            if not options:
                route_list.append((network, None))

            elif len(options) == 2 and options[0] == 'tag':
                if options[1].isdigit():
                    route_list.append((network, options[1]))
                else:
                    raise ValueError('invalid tag')

            else:
                raise ValueError('invalid route options')

        except ValueError as e:
            print(f'ignoring invalid route attribute: {attr_value}: {e}')

    return route_list


# Function to run multiple vtysh configure commands on the same socket session
def run_vtysh_cmds(socket_path, commands):
    try:
        # Create a Unix socket connection
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.connect(socket_path)
            # Send each command in the list
            for cmd in commands:
                # Send the command with a null byte appended
                client.sendall(cmd.encode() + b'\x00')
                # Receive the response until the null byte
                while True:
                    data = client.recv(4096)
                    if not data:
                        # Socket is disconnected
                        break
                    if data[-1] == 0:
                        # All data received
                        break
    except Exception as e:
        raise RuntimeError(f'Failed to run commands: {e}') from e


def edit_routes_socket(add, routes, tunnel_name, netns_priv, l3vrf_name):
    """
    Add or remove the routes supplied through RADIUS attributes using the vty socket.

    :arg Bool add:
        Whether the routes should be added or removed.
    :arg List routes:
        List of (network, tag) tuples, as returned by create_route_list().
    :arg String tunnel_name:
        Name of the tunnel interface used as a next-hop for the routes.
    :arg String netns_priv:
        Name of the network namespace in which the routes should be edited.
    :arg String l3vrf_name:
        Name of the l3vrf in which to install the routes.
    """
    vtysh_cmds = ['enable', 'configure terminal']

    l3vrf_arg = f' vrf {l3vrf_name}' if l3vrf_name else ''

    if add:
        cmd_prefix = 'ip route '
    else:
        cmd_prefix = 'no ip route '

    for network, tag in routes:
        tag_arg = f' tag {tag}' if tag is not None else ''
        vtysh_cmds += [f'{cmd_prefix}{network} {tunnel_name}{l3vrf_arg}{tag_arg}']

    assert netns_priv == 'main'
    vty_socket = f'/run/{VTY_SOCKET_POST}'

    try:
        run_vtysh_cmds(vty_socket, vtysh_cmds)

    except RuntimeError:
        print('failed to {} routes'.format('add' if add else 'remove'), file=sys.stderr)


def edit_routes_vtysh(add, routes, tunnel_name, netns_priv, l3vrf_name):
    """
    Add or remove the routes supplied through RADIUS attributes using vtysh.

    :arg Bool add:
        Whether the routes should be added or removed.
    :arg List routes:
        List of (network, tag) tuples, as returned by create_route_list().
    :arg String tunnel_name:
        Name of the tunnel interface used as a next-hop for the routes.
    :arg String netns_priv:
        Name of the network namespace in which the routes should be edited.
    :arg String l3vrf_name:
        Name of the l3vrf in which to install the routes.
    """
    l3vrf_arg = f' vrf {l3vrf_name}' if l3vrf_name else ''

    if add:
        cmd_prefix = 'ip route '
    else:
        cmd_prefix = 'no ip route '

    with NamedTemporaryFile(mode='w') as cmdfile:
        for network, tag in routes:
            tag_arg = f' tag {tag}' if tag is not None else ''
            cmdfile.write(f'{cmd_prefix}{network} {tunnel_name}{l3vrf_arg}{tag_arg}\n')

        cmdfile.flush()
        ip_netns_exec = ['ip', 'netns', 'exec', netns_priv] if netns_priv != 'main' else []
        run([*ip_netns_exec, 'vtysh', '--daemon', FRR_DAEMON, '--inputfile', cmdfile.name], check=True)


def main():
    ap = ArgumentParser()
    ap.add_argument('action', action='store', choices={'add','del'})
    ap.add_argument('ifname', action='store')
    ap.add_argument('-d', '--dynamic', action='store', nargs=2, metavar=('local','remote'))
    ap.add_argument('-n', '--netns', action='store', default=SCRIPT_NETNS)
    ap.add_argument('-v', '--l3vrf', action='store')
    ap.add_argument('-m', '--method', action='store', choices={'socket','vtysh'}, default='socket')
    ap.add_argument('routes', action='store', nargs='+')

    args = ap.parse_args()

    add = args.action == 'add'

    if args.dynamic and add:
        create_tunnel_interface(args.ifname, args.dynamic[0], args.dynamic[1], args.netns, args.l3vrf)

    try:
        routes = create_route_list(args.routes)

        if args.method == 'socket':
            edit_routes_socket(add, routes, args.ifname, args.netns, args.l3vrf)
        else:
            edit_routes_vtysh(add, routes, args.ifname, args.netns, args.l3vrf)

    except Exception as e:
        delete_tunnel_interface(args.ifname, args.netns)
        print(f'failed to edit routes: {e}', file=sys.stderr)

    if args.dynamic and not add:
        delete_tunnel_interface(args.ifname, args.netns)


if __name__ == '__main__':
    main()
