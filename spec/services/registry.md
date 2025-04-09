# Resource Registry
The registry service allows programs to resolve resources provided by other components by name.
This allows client processes to discover server processes and also provides some access control.

## Data Model
The registry service provides a hierarchical namespace.
Each namespace has a name and can contain subnamespaces or resources.
Each resource is identified by a unique path string.
Paths are UTF-8 strings where `/`s delimits a sequence of names representing a path through the resource namespace hierarchy.
Namespace names can be strings of any UTF-8 characters except `/`.

### Root Organization
The root namespace contains the following top level subnamespaces:

- `device`: resources related to device drivers.
- `service`: resources related to system services that are not strictly device drivers.
- `volume`: resources that represent file systems.

## RPC Methods
The registry service provides the following methods using the basic RPC protocol.

### Register Resource Provider
Registers the calling process/thread as a resource provider.

#### Parameters:
- Root path for the provider
- Properties: read only?

### Unregister Resource Provider
Unregisters the calling process/thread as a resource provider.

### Lookup Resource
Looks up a resource by path to determine its provider.

#### Parameters
- Path of the resource

#### Returns
- The byte index into the path that splits the provider path from the provider relative resource path
- The PID and TID of the provider.

### List Subresources

## Resource Provider Protocol
Resource providing services must adher to this protocol.

- proxyed requests for Lookup, List, Create, Delete
    - paths made relative to root of provider
    - original caller's pid/tid provided
- must return to the original caller: handle (u32), size of resource (?)


---

ok but like, does the registry need such complex proxying and create/delete mechanisms?
upside is that it reduces the number of messages sent (kind of) and mildly reduces the complexity on the client side
downside is that it increases the complexity of the service
also, it means that the providers are 100% responsible for the protocol they use to communicate

basically this means we'd have:
- lookup(path) -> split index, pid/tid of provider service
- list(path) -> list of providers under a prefix

tbh the proxying is actually a superset of functionality, so we could start without it and then add it later as a convenience/perf boost
