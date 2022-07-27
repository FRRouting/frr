from ipaddress import IPv4Address, IPv6Address

__all__ = [
    "v4addr",
    "v4net",
    "v6addr",
    "fmt_candidates",
    "fmt_label_blocks",
    "fmt_policies",
]


def v4addr(idx, v4base, skip=1, with_masklen=True):
    addr = IPv4Address(int(v4base.network_address) + skip * idx + 1)
    if with_masklen:
        return f"{addr}/{v4base.prefixlen}"
    return f"{addr}"


def v4net(idx, v4base, host=False, offset=1):
    if not host:
        offset = 0
    addr = IPv4Address(
        int(v4base.network_address) + idx * v4base.num_addresses + offset
    )
    return f"{addr}/{v4base.prefixlen}"


def v6addr(idx, v6base, skip=1, with_masklen=True):
    addr = IPv6Address(int(v6base.network_address) + skip * idx + 1)
    if with_masklen:
        return f"{addr}/{v6base.prefixlen}"
    return f"{addr}"


def v6net(idx, v6base, host=False, offset=1):
    if not host:
        offset = 0
    addr = IPv6Address(
        int(v6base.network_address) + idx * v6base.num_addresses + offset
    )
    return f"{addr}/{v6base.prefixlen}"


def fmt_candidates(policy, indent, remove=False):
    cmd = ""
    for cand in policy["candidate-path"]:
        cmd += f'{" "*indent}'
        if remove:
            cmd += (
                f"no candidate-path preference"
                + f' {cand["preference"]} name {cand["name"]} flex-algo\n'
            )
        else:
            cmd += (
                f"candidate-path preference"
                + f' {cand["preference"]} name {cand["name"]}'
                + f' flex-algo {cand["flex-algo"]}\n'
            )
    return cmd


def fmt_label_blocks(block, indent, remove=False, remove_cand=False):
    cmd = f"configure terminal\n segment-routing\n  traffic-eng\n"
    if remove:
        return cmd
    cmd += f'{" "*indent}policy-label-blocks template {block["binding-sid-lower"]} {block["binding-sid-upper"]}'
    return cmd


def fmt_policies(policies, indent, remove=False, remove_cand=False):
    cmd = f"configure terminal\n segment-routing\n  traffic-eng\n"
    for color, policy in policies.items():
        if remove:
            cmd += f'{" "*indent}no policy-template color {color}\n'
        else:
            cmd += f'{" "*indent}policy-template color {color}\n'
            cmd += fmt_candidates(policy, indent + 1, remove_cand)
            cmd += f'{" "*indent}exit\n'
    return cmd
