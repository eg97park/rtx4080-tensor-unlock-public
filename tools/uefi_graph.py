"""Offline UEFI open-protocol relationships, never a detach/boot permission.

UEFI 2.11 section 7.3 and pinned EDK2 UefiSpec.h define the open modes.
Only BY_CHILD_CONTROLLER creates an observed parent -> child edge. GET_PROTOCOL
is a reference, not ownership. ConSplitter can make the same virtual console a
child of both GPUs; an unequal ConsoleOutHandle does not establish isolation.
The probe walks the database sequentially, so even a well-formed graph is not
an atomic snapshot or proof that unrecorded firmware references do not exist.
"""
from collections import deque
import uuid

from uefi_path import decode

# Full GUIDs below are from the pinned MdePkg protocol headers.
PCI_IO = '4cf5b200-68b8-4ca5-9eec-b23e3f50029a'
GOP = '9042a9de-23dc-4a38-96fb-7aded080516a'
DRIVER_BINDING = '18a031ab-b443-4d1a-a5c0-0c09261e9f71'
LOADED_IMAGE = '5b1b31a1-9562-11d2-8e3f-00a0c969723b'
TEXT_OUT = '387477c2-69c7-11d2-8e39-00a0c969723b'
# This PC's Intel GPU ID was independently observed in the Windows inventory.
# Other Intel PCI devices are deliberately not classified as display devices.
INTEL_DISPLAY_ID = 0x7d678086
OPEN_MODES = {1: 'by_handle', 2: 'get_protocol', 4: 'test_protocol',
              8: 'by_child_controller', 16: 'by_driver',
              32: 'exclusive', 48: 'by_driver_exclusive'}
META = {'device_path', 'driver_image', 'driver_binding_handle', 'driver_version',
        'image_base', 'image_size', 'image_device', 'mapped_image_sha256'}


def _integer(value, name, limit=0xffffffffffffffff):
    if type(value) is not int or not 0 <= value <= limit:
        raise ValueError('invalid graph integer: ' + name)
    return value


def analyze_graph(pairs: list[tuple[str, int | bytes]]) -> tuple[list[dict], dict]:
    """Return compatible raw handle records and a conservative relationship review.

    Malformed/contradictory records raise; absent observations remain explicit
    issues. Neither a complete graph nor absence of a known conflict allows a
    disconnect. All handle identifiers are local to this single capture.
    """
    issues = []

    def unique(key):
        values = [v for k, v in pairs if k == key]
        if len(values) > 1:
            raise ValueError('duplicate graph context: ' + key)
        if not values:
            issues.append('missing ' + key)
            return 0
        return _integer(values[0], key)

    target = unique('target_handle')
    console = unique('console_out_handle')
    count = unique('handle_count')
    if count > 4096:
        raise ValueError('handle count exceeds probe bound')
    nodes = {}; raw_graph = []; current = None; ended = False
    intel = {}; entries = []; protocol = None; pending = []
    for i, (key, value) in enumerate(pairs):
        if key in ('intel_pci_handle', 'target_handle'):
            if pending:
                raise ValueError('truncated protocol open entry')
            ended = True; current = None
        if key == 'intel_pci_handle':
            handle = _integer(value, key)
            if not handle or handle in intel or i + 1 >= len(pairs) or pairs[i + 1][0] != 'intel_pci_id':
                raise ValueError('invalid/duplicate Intel PCI record')
            ident = _integer(pairs[i + 1][1], 'intel_pci_id', 0xffffffff)
            if ident & 0xffff != 0x8086:
                raise ValueError('Intel record has a different vendor')
            intel[handle] = ident
        elif key == 'intel_pci_id':
            if not i or pairs[i - 1][0] != 'intel_pci_handle':
                raise ValueError('orphan Intel PCI ID')
        elif key == 'handle':
            handle = _integer(value, key)
            if ended or pending or not handle or handle in nodes or len(nodes) >= 4096:
                raise ValueError('invalid/duplicate/out-of-order graph handle')
            current = {'handle': hex(handle), 'metadata': {}, 'protocols': [], 'opens': []}
            nodes[handle] = current; protocol = None
            raw_graph.append({'handle': hex(handle), 'records': []})
        elif current is not None:
            raw_graph[-1]['records'].append([key, value.hex() if isinstance(value, bytes) else hex(value)])
            if key in META:
                if protocol is not None or key in current['metadata']:
                    raise ValueError('duplicate/out-of-order handle metadata')
                if key == 'device_path':
                    if not isinstance(value, bytes): raise ValueError('invalid device path type')
                    decode(value)
                elif key == 'mapped_image_sha256':
                    if not isinstance(value, bytes) or len(value) != 32: raise ValueError('invalid image hash')
                else:
                    _integer(value, key, 0xffffffff if key == 'driver_version' else 0xffffffffffffffff)
                current['metadata'][key] = value.hex() if isinstance(value, bytes) else hex(value)
            elif key == 'protocol_guid':
                if pending or not isinstance(value, bytes) or len(value) != 16:
                    raise ValueError('invalid protocol GUID or truncated open entry')
                protocol = str(uuid.UUID(bytes_le=value))
                if protocol in current['protocols'] or len(current['protocols']) >= 128:
                    raise ValueError('duplicate protocol or protocol count exceeded')
                current['protocols'].append(protocol)
            elif key in ('agent', 'controller', 'attributes', 'open_count'):
                order = ('agent', 'controller', 'attributes', 'open_count')
                if protocol is None or key != order[len(pending)]:
                    raise ValueError('out-of-order protocol open entry')
                pending.append(_integer(value, key, 0xffffffff if len(pending) >= 2 else 0xffffffffffffffff))
                if len(pending) == 4:
                    agent, controller, attr, opened = pending; pending = []
                    if attr not in OPEN_MODES or not opened or (attr in (8, 16, 32, 48) and not agent) or (attr in (8, 16, 48) and not controller):
                        raise ValueError('invalid protocol open attributes/count/handles')
                    if attr == 8 and hex(controller) == current['handle']:
                        raise ValueError('child controller cannot equal its parent')
                    entry = {'handle': current['handle'], 'protocol': protocol, 'agent': hex(agent),
                             'controller': hex(controller), 'attributes': attr,
                             'mode': OPEN_MODES[attr], 'open_count': opened}
                    if any(all(e[k] == entry[k] for k in ('protocol', 'agent', 'controller', 'attributes'))
                           for e in current['opens']):
                        raise ValueError('duplicate protocol open entry')
                    if sum(e['protocol'] == protocol for e in current['opens']) >= 256:
                        raise ValueError('protocol open count exceeds probe bound')
                    current['opens'].append(entry); entries.append(entry)
            else:
                raise ValueError('unknown handle record: ' + key)
        elif key in META | {'protocol_guid', 'agent', 'controller', 'attributes', 'open_count'}:
            raise ValueError('orphan handle record: ' + key)
    if pending:
        raise ValueError('truncated protocol open entry')
    if count != len(nodes): issues.append('handle_count does not match captured graph')
    if not nodes: issues.append('no handle graph captured')

    def reference(handle, reason):
        if handle and handle not in nodes: issues.append(reason + ': ' + hex(handle))

    reference(target, 'target missing from graph'); reference(console, 'console missing from graph')
    if not target or PCI_IO not in nodes.get(target, {}).get('protocols', []):
        issues.append('target PCI I/O protocol not observed')
    if not console or TEXT_OUT not in nodes.get(console, {}).get('protocols', []):
        issues.append('ConsoleOut text protocol not observed')
    for handle, node in nodes.items():
        if not node['protocols']: issues.append('no protocols on ' + hex(handle))
        for protocol in node['protocols']:
            owners = [e for e in node['opens'] if e['protocol'] == protocol and e['attributes'] in (16, 32, 48)]
            if len(owners) > 1:
                issues.append('contradictory driver/exclusive owners: ' + hex(handle) + '/' + protocol)
        meta = node['metadata']
        binding = {'driver_image', 'driver_binding_handle', 'driver_version'}
        if DRIVER_BINDING in node['protocols'] or binding.intersection(meta):
            if not binding.issubset(meta) or DRIVER_BINDING not in node['protocols']:
                issues.append('incomplete driver binding: ' + hex(handle))
            else:
                image = int(meta['driver_image'], 16)
                if int(meta['driver_binding_handle'], 16) != handle:
                    issues.append('driver binding handle mismatch: ' + hex(handle))
                if not image or LOADED_IMAGE not in nodes.get(image, {}).get('protocols', []):
                    issues.append('driver loaded image not observed: ' + hex(handle))
        for key in ('driver_image', 'driver_binding_handle', 'image_device'):
            if key in meta: reference(int(meta[key], 16), 'unresolved ' + key)
        image_fields = {'image_base', 'image_size', 'image_device'}
        if LOADED_IMAGE in node['protocols'] or image_fields.intersection(meta) or 'mapped_image_sha256' in meta:
            if not image_fields.issubset(meta) or LOADED_IMAGE not in node['protocols']:
                issues.append('incomplete loaded image: ' + hex(handle))
            elif int(meta['image_base'], 16) and 0 < int(meta['image_size'], 16) <= 32 * 1024 * 1024 and 'mapped_image_sha256' not in meta:
                issues.append('mapped image hash missing: ' + hex(handle))
    unresolved_agents=[]
    children = {h: set() for h in nodes}
    for entry in entries:
        source, agent, child = (int(entry[k], 16) for k in ('handle', 'agent', 'controller'))
        reference(agent, 'unresolved open agent'); reference(child, 'unresolved open controller')
        if agent and agent not in nodes:
            # EDK2 CoreOpenProtocol does not validate AgentHandle for GET,
            # TEST or BY_HANDLE. Range association explains an observation;
            # it must never turn an address into a driver ownership handle.
            candidates=[]
            for image_handle,node in nodes.items():
                meta=node['metadata']
                if LOADED_IMAGE not in node['protocols']:continue
                base=int(meta.get('image_base','0'),16);size=int(meta.get('image_size','0'),16)
                if base and 0<size<=32*1024*1024 and base+size<=1<<64 and base<=agent<base+size:
                    candidates.append({'image_handle':hex(image_handle),'offset':hex(agent-base)})
            unresolved_agents.append({**entry,'non_owning_reference':entry['attributes'] in (1,2,4),
                'address_in_loaded_images':candidates,'valid_handle_proven':False})
        if entry['attributes'] in (8, 16, 48) and DRIVER_BINDING not in nodes.get(agent, {}).get('protocols', []):
            issues.append('driver-model agent binding not observed: ' + hex(agent))
        if entry['attributes'] == 8:
            children[source].add(child)
    # Kahn's algorithm detects cycles without recursion, including long chains.
    indegree = {h: 0 for h in nodes}
    for neighbors in children.values():
        for h in neighbors:
            if h in indegree: indegree[h] += 1
    queue = deque(h for h, n in indegree.items() if not n); visited = 0
    while queue:
        h = queue.popleft(); visited += 1
        for child in children[h]:
            if child in indegree:
                indegree[child] -= 1
                if not indegree[child]: queue.append(child)
    cycle = visited != len(nodes)
    if cycle: issues.append('cycle in observed child-controller graph')

    def closure(roots):
        parent = {h: None for h in roots if h in nodes}; queue = deque(parent)
        while queue:
            h = queue.popleft()
            for child in sorted(children[h]):
                if child in nodes and child not in parent:
                    parent[child] = h; queue.append(child)
        path = []; h = console
        while h in parent:
            path.append(hex(h)); h = parent[h]
        return set(parent), list(reversed(path))

    intel_display = [h for h, ident in intel.items() if ident == INTEL_DISPLAY_ID]
    if target in intel: issues.append('target is also labelled as an Intel PCI device')
    for h in intel:
        reference(h, 'Intel PCI handle missing from graph')
        if PCI_IO not in nodes.get(h, {}).get('protocols', []): issues.append('Intel PCI I/O protocol not observed: ' + hex(h))
    if len(intel_display) != 1: issues.append('expected one independently identified Intel 7d67 display device')
    target_set, target_path = closure([target]); intel_set, intel_path = closure(intel_display)

    def describe(reachable, path):
        managed = [e for e in entries if int(e['handle'], 16) in reachable and e['attributes'] in (16, 48)]
        agents = {int(e['agent'], 16) for e in managed}
        images = {int(nodes[a]['metadata']['driver_image'], 16) for a in agents
                  if a in nodes and 'driver_image' in nodes[a]['metadata']}
        return {'reachable_handles': [hex(h) for h in sorted(reachable)],
                'gop_handles': [hex(h) for h in sorted(reachable) if GOP in nodes[h]['protocols']],
                'observed_path_to_console_out': path, 'driver_opens': managed,
                'exclusive_opens': [e for e in entries if int(e['handle'], 16) in reachable and e['attributes'] in (32, 48)],
                'driver_agents': [hex(h) for h in sorted(agents)], 'driver_images': [hex(h) for h in sorted(images)]}

    nvidia_view = describe(target_set, target_path); intel_view = describe(intel_set, intel_path)
    conflicts = []
    if nvidia_view['exclusive_opens']: conflicts.append('existing exclusive protocol user in NVIDIA closure')
    if target_path: conflicts.append('NVIDIA reaches active ConsoleOut through observed child relationships')
    shared = target_set & intel_set
    if shared: conflicts.append('Intel and NVIDIA have shared descendants/roots')
    shared_images = sorted(set(nvidia_view['driver_images']) & set(intel_view['driver_images']))
    if shared_images: conflicts.append('Intel and NVIDIA paths reference a shared driver image; unloading is not isolated')
    if not intel_path: issues.append('no observed Intel path to ConsoleOut; screen preservation remains unproven')
    if not intel_view['gop_handles']: issues.append('Intel GOP not observed in child closure')
    return raw_graph, {'schema_version': 1, 'handle_count': len(nodes), 'open_entry_count': len(entries),
        'structural_observations_complete': not issues, 'issues': sorted(set(issues)), 'conflicts': conflicts,
        'target': nvidia_view, 'intel_display': intel_view,
        'intel_other_pci_handles': [hex(h) for h in sorted(intel) if h not in intel_display],
        'shared_handles': [hex(h) for h in sorted(shared)], 'shared_driver_images': shared_images,
        'unresolved_open_agents':unresolved_agents,
        'child_edges': [e for e in entries if e['attributes'] == 8], 'cycle_detected': cycle,
        'detach_ready': False, 'console_preservation_proven': False,
        'limitations': ['Sequential snapshot; unrecorded firmware references can exist.',
                       'GET_PROTOCOL/TEST_PROTOCOL/by-handle references are not ownership edges.',
                       'No conflict observed does not authorize disconnect, reset, unload or GPU writes.',
                       'Handles and relocated image hashes are session-local, not cross-boot pins.']}
