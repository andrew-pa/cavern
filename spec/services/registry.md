# Resource Registry
The registry service allows programs to resolve resources provided by other components by name.
This allows client processes to discover server processes and also provides some access control.

## Data Model
The registry service provides a hierarchical namespace.
Each namespace has a name and can contain subnamespaces or resources.
Each resource is identified by a unique path string.
Paths are UTF-8 strings where `/`s delimits a sequence of names representing a path through the resource namespace hierarchy.

### Root Organization
The root namespace contains the following top level subnamespaces:

- `device`: resources related to device drivers.
- `service`: resources related to system services that are not strictly device drivers.
- `volume`: resources that represent file systems.

## RPC Methods
The registry service provides the following methods using the basic RPC protocol.

### Register Resource Provider
### Unregister Resource Provider
### Lookup Resource
### Create Resource
### List Subresources

## Resource Provider Protocol
Resource providing services must adher to this protocol.
